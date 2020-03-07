// +build !windows

// Copyright 2017 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package srv6

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	cniip "github.com/containernetworking/plugins/pkg/ip"
	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	ipt "github.com/coreos/go-iptables/iptables"
	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/net/context"
)

const (
	backendType = "srv6"
	addrPrefix = "fd12:3456:789a"
	addrPrefixLength = 48
)

type srv6LeaseAttrs struct {
	MACAddr net.HardwareAddr
}

func enableSRv6(deviceName string) error {
	for _, dev := range []string{"all", deviceName} {
		seg6Enabled := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/seg6_enabled", dev)

		err := echoToFile(seg6Enabled, 1)
		if err != nil {
			return err
		}

		hmacDisabled := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/seg6_require_hmac", dev)

		err = echoToFile(hmacDisabled, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

func echoToFile(f string, value int) error {
	// Copied from ip package `echo1`
	valueStr := strconv.Itoa(value)

	err := readFromFile(f)
	if err != nil {
		return err
	}

	if content, err := ioutil.ReadFile(f); err == nil {
		if bytes.Equal(bytes.TrimSpace(content), []byte(valueStr)) {
			return nil
		}
	}
	err = ioutil.WriteFile(f, []byte(valueStr), 0644)

	if err != nil {
		return err
	}

	return readFromFile(f)
}

func readFromFile(f string) error {
	content, err := ioutil.ReadFile(f)
	if err != nil {
		log.Errorf("Cannot read %s\n", f)
		return err
	}

	contentInt := int(bytes.TrimSpace(content)[0])
	log.Errorf("Read %s: %d\n", f, contentInt)

	return nil
}

func computeIPv6AddrFromIP(ipAddr ip.IP4) string {
	a, b, c, d := ipAddr.Octets()
	IPv6Addr := fmt.Sprintf("%s:%02x%02x:%02x%02x:0000:0000:0001", addrPrefix, a, b, c, d)

	return IPv6Addr
}

func ensurePodNetworkFilter(subnet string) error {
	iptables, err := ipt.New()
	if err != nil {
		log.Warningf("ensurePodNetworkFilter.New ", err)
		return err
	}

	listChain, err := iptables.List("filter", "FORWARD")
	if err != nil {
		log.Warningf("ensurePodNetworkFilter.List ", err)
		return err
	}

	dest := "-d " + subnet
	src := "-s " + subnet

	destAssigned := false
	srcAssigned := false
	kubeFWDIndex := -1
	for i, chain := range listChain {
		if strings.Contains(chain, "KUBE-FORWARD") {
			kubeFWDIndex = i
			break
		}

		if !strings.Contains(chain, "-A FORWARD") {
			continue
		}

		if !strings.Contains(chain, "-j ACCEPT") {
			continue
		}

		if strings.Contains(chain, src) {
			srcAssigned = true
			continue
		}

		if strings.Contains(chain, dest) {
			destAssigned = true
			continue
		}
	}

	if kubeFWDIndex != -1 {
		if !srcAssigned {
			err = iptables.Insert("filter", "FORWARD", kubeFWDIndex, "-s", subnet, "-j", "ACCEPT")
			if err != nil {
				log.Warningf("ensurePodNetworkFilter.Insert ", err)
				return err
			}
		}

		if !destAssigned {
			err = iptables.Insert("filter", "FORWARD", kubeFWDIndex, "-d", subnet, "-j", "ACCEPT")
			if err != nil {
				log.Warningf("ensurePodNetworkFilter.Insert ", err)
				return err
			}
		}
	} else {
		log.Warningf("KUBE-FORWARD is not found. skipping...")
	}

	return nil
}

func setSRTunnelSrc(ipAddr string) {
	out, err := exec.Command("/sbin/ip", "sr", "tunsrc", "set", ipAddr).Output()
	if err != nil {
		log.Warningf("setSRTunnelSrc: ", err)
	}
	log.Infof("setSRTunnelSrc: %s", out)
}

func init() {
	backend.Register(backendType, New)
}

type SRv6Backend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := &SRv6Backend{
		sm:       sm,
		extIface: extIface,
	}
	return be, nil
}

func (be *SRv6Backend) RegisterNetwork(ctx context.Context, wg sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	cfg := struct {
		DirectRouting bool
	}{}

	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding SRv6 backend config: %v", err)
		}
	}

	// Note(yuichiro_ueno):
	// Actually IP Forwarding Enabling feature should be implemented in the CNI implementation (i.e. bridge.go).
	// However, currently we use IPv4 networking on k8s but actually use SRv6 in flanneld.
	// Thus we should change the forwarding mode here.
	cniip.EnableIP6Forward()

	err := enableSRv6(be.extIface.Iface.Name)
	if err != nil {
		return nil, err
	}

	n := &SRv6Network{
		SimpleNetwork: backend.SimpleNetwork{
			ExtIface: be.extIface,
		},
		SM:          be.sm,
		BackendType: backendType,
	}

	mac, err := json.Marshal(&srv6LeaseAttrs{MACAddr: be.extIface.Iface.HardwareAddr})
	if err != nil {
		return nil, err
	}

	attrs := &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: backendType,
		BackendData: json.RawMessage(mac),
	}

	l, err := be.sm.AcquireLease(ctx, attrs)
	switch err {
	case nil:
		n.SubnetLease = l
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// TODO: Assume L2-connectivity
	IPv6Addr := computeIPv6AddrFromIP(ip.FromIP(be.extIface.ExtAddr))
	IPv6AddrPrefix := fmt.Sprintf("/%d", addrPrefixLength)

	netlinkIPv6Subnet, err := netlink.ParseAddr(IPv6Addr + IPv6AddrPrefix)
	if err != nil {
		log.Warningf("netlink.ParseAddr: ", err)
		return nil, err
	}

	directConnectedRoute := netlink.Route{
		Dst: netlinkIPv6Subnet.IPNet,
		LinkIndex: be.extIface.Iface.Index,
	}
	err = netlink.RouteReplace(&directConnectedRoute)
	if err != nil {
		log.Warningf("netlink.RouteAdd(directConnectedRoute): ", directConnectedRoute, err)
		return nil, err
	}

	myNeigh := netlink.Neigh{
		LinkIndex:      be.extIface.Iface.Index,
		IP:             netlinkIPv6Subnet.IP,
		HardwareAddr:   be.extIface.Iface.HardwareAddr,
		State:          netlink.NUD_PERMANENT,
	}
	err = netlink.NeighSet(&myNeigh)
	if err != nil {
		log.Warningf("netlink.NeighSet(myNeigh): ", myNeigh, err)
		return nil, err
	}

	netlinkIPv6OnlySubnet, err := netlink.ParseAddr(IPv6Addr + "/128")
	if err != nil {
		log.Warningf("netlink.ParseAddr: ", err)
		return nil, err
	}

	endFunction := netlink.SEG6LocalEncap{
		Action: nl.SEG6_LOCAL_ACTION_END_DX4,
		InAddr: net.IPv4(0, 0, 0, 0),
	}
	endFunction.Flags[nl.SEG6_LOCAL_NH4] = true

	decapRoute := netlink.Route{
		Dst: netlinkIPv6OnlySubnet.IPNet,
		LinkIndex: be.extIface.Iface.Index,
		Encap: &endFunction,
	}
	err = netlink.RouteReplace(&decapRoute)
	if err != nil {
		log.Warningf("netlink.RouteAdd(decapRoute): ", decapRoute, err)
		return nil, err
	}

	err = ensurePodNetworkFilter(l.Subnet.ToIPNet().String())
	if err != nil {
		return nil, err
	}

	setSRTunnelSrc(IPv6Addr)

	// TODO: Handle SRv6 header size ?
	n.Mtu = be.extIface.Iface.MTU
	n.LinkIndex = be.extIface.Iface.Index
	n.GetRouteAndNeigh = func(lease *subnet.Lease) (*netlink.Route, *netlink.Neigh) {
		// TODO: No direct routing support

		destIPv6 := net.ParseIP(computeIPv6AddrFromIP(lease.Attrs.PublicIP))

		var srv6Attrs srv6LeaseAttrs
		if err := json.Unmarshal(lease.Attrs.BackendData, &srv6Attrs); err != nil {
			log.Error("error decoding subnet lease JSON: ", err)
			return nil, nil
		}

		neigh := netlink.Neigh{
			LinkIndex:      be.extIface.Iface.Index,
			IP:             destIPv6,
			HardwareAddr:   srv6Attrs.MACAddr,
			State:          netlink.NUD_PERMANENT,
		}

		log.Info("configure neigh: ", neigh)

		encap := netlink.SEG6Encap{
			Mode:      nl.SEG6_IPTUN_MODE_ENCAP,
			Segments:  []net.IP{destIPv6},
		}

		route := netlink.Route{
			Dst:       lease.Subnet.ToIPNet(),
			LinkIndex: n.ExtIface.Iface.Index,
			Encap:     &encap,
		}

		log.Info("configure route: ", route)

		return &route, &neigh
	}

	return n, nil
}
