package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
)

const ipopBrName = "ipopBr0"

type NetConf struct {
	types.NetConf
	BrName      string `json:"bridge"`
	IsGW        bool   `json:"isGateway"`
	IsDefaultGW bool   `json:"isDefaultGateway"`
}

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{
		BrName: ipopBrName,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load network configuration: %v", err)
	}
	log.Printf("%+v", *n)
	return n, n.CNIVersion, nil
}

func setupBridge(netconf *NetConf) (*netlink.Bridge, *current.Interface, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:   netconf.BrName,
			MTU:    1500,
			TxQLen: -1,
		},
	}

	err := netlink.LinkAdd(br)
	if err != nil && err != syscall.EEXIST {
		return nil, nil, err
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, nil, err
	}
	return br, &current.Interface{
		Name: br.Attrs().Name,
		Mac:  br.Attrs().HardwareAddr.String(),
	}, nil
}

func setupVeth(br *netlink.Bridge, netconf *NetConf, args *skel.CmdArgs) (*current.Interface, *current.Interface, error) {
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		log.Fatalf("Could not find network namespace %v", err)
		return nil, nil, fmt.Errorf("Could not find network namespace %v", err)
	}
	contIface := &current.Interface{}
	hostIface := &current.Interface{}
	var handler = func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err := ip.SetupVeth(args.IfName, 1500, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		log.Printf("Created pod veth interface: %v\n", containerVeth.Name)
		return nil
	}
	if err := netns.Do(handler); err != nil {
		return nil, nil, err
	}
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Located host veth interface: %v\n", hostVeth.Attrs().Name)
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		return nil, nil, err
	}
	log.Printf("Attached %v to %v\n", hostVeth.Attrs().Name, br.Name)

	return hostIface, contIface, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	log.Printf("%v\t %v\t %v", args.ContainerID, args.IfName, args.Netns)
	log.Println("parsed configuration successfully !")
	br, brInterface, err := setupBridge(n)
	if err != nil {
		return err
	}
	log.Printf("set up bridge %v successfully !\n", br.Name)
	hostInterface, containerInterface, err := setupVeth(br, n, args)
	if err != nil {
		return err
	}
	log.Println("set up veth interfaces successfully !")

	result := &current.Result{CNIVersion: cniVersion, Interfaces: []*current.Interface{brInterface, hostInterface, containerInterface}}
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	var success bool = false
	// release IP in case of failure
	defer func() {
		if !success {
			os.Setenv("CNI_COMMAND", "DEL")
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
			os.Setenv("CNI_COMMAND", "ADD")
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		log.Printf("could not convert IPAM result %+v \n", ipamResult)
		return err
	}
	log.Printf("result from IPAM : %+v\n", ipamResult)
	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes

	if len(result.IPs) == 0 {
		log.Printf("IPAM plugin provided no IP config\n")
		return errors.New("IPAM plugin returned missing IP config")
	}
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		log.Printf("could not find namespace %v", args.Netns)
		return err
	}
	for _, ipc := range result.IPs {
		ipc.Interface = current.Int(2)
	}

	gwsV4, gwsV6, err := calcGateways(result, n)
	if err != nil {
		return err
	}
	// Configure the container hardware address and IP address(es)
	if err := netns.Do(func(_ ns.NetNS) error {
		contVeth, err := net.InterfaceByName(args.IfName)
		if err != nil {
			log.Printf("could not find interface %v", contVeth.Name)
			return err
		}
		// Add the IP to the interface
		if err := ipam.ConfigureIface(args.IfName, result); err != nil {
			log.Printf("could not configure IP address on the interface %v", args.IfName)
			return err
		}

		// Send a gratuitous arp
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	}); err != nil {
		log.Printf("something went wrong while trying to configure IP address on the interface !")
		return err
	}
	if n.IsGW {
		// Set the IP address(es) on the bridge and enable forwarding
		for _, gws := range []*gwInfo{gwsV4, gwsV6} {
			if gws.gws != nil {
				if err = enableIPForward(gws.family); err != nil {
					return fmt.Errorf("failed to enable forwarding: %v", err)
				}
			}
		}
	}
	l, err := netlink.LinkByName(br.Name)
	if err != nil {
		log.Printf("could not lookup %q: %v", br.Name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		log.Printf("%q already exists but is not a bridge", br.Name)
	}
	log.Printf("result %v\n", result)
	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "ipop cni plugin")
}

func enableIPForward(family int) error {
	if family == netlink.FAMILY_V4 {
		return ip.EnableIP4Forward()
	}
	return ip.EnableIP6Forward()
}

func calcGateways(result *current.Result, n *NetConf) (*gwInfo, *gwInfo, error) {

	gwsV4 := &gwInfo{}
	gwsV6 := &gwInfo{}

	for _, ipc := range result.IPs {

		// Determine if this config is IPv4 or IPv6
		var gws *gwInfo
		defaultNet := &net.IPNet{}
		switch {
		case ipc.Address.IP.To4() != nil:
			gws = gwsV4
			gws.family = netlink.FAMILY_V4
			defaultNet.IP = net.IPv4zero
		case len(ipc.Address.IP) == net.IPv6len:
			gws = gwsV6
			gws.family = netlink.FAMILY_V6
			defaultNet.IP = net.IPv6zero
		default:
			return nil, nil, fmt.Errorf("Unknown IP object: %v", ipc)
		}
		defaultNet.Mask = net.IPMask(defaultNet.IP)

		// All IPs currently refer to the container interface
		ipc.Interface = current.Int(2)

		// If not provided, calculate the gateway address corresponding
		// to the selected IP address
		if ipc.Gateway == nil && n.IsGW {
			ipc.Gateway = calcGatewayIP(&ipc.Address)
		}

		// Add a default route for this family using the current
		// gateway address if necessary.
		if n.IsDefaultGW && !gws.defaultRouteFound {
			for _, route := range result.Routes {
				if route.GW != nil && defaultNet.String() == route.Dst.String() {
					gws.defaultRouteFound = true
					break
				}
			}
			if !gws.defaultRouteFound {
				result.Routes = append(
					result.Routes,
					&types.Route{Dst: *defaultNet, GW: ipc.Gateway},
				)
				gws.defaultRouteFound = true
			}
		}

		// Append this gateway address to the list of gateways
		if n.IsGW {
			gw := net.IPNet{
				IP:   ipc.Gateway,
				Mask: ipc.Address.Mask,
			}
			gws.gws = append(gws.gws, gw)
		}
	}
	return gwsV4, gwsV6, nil
}

func calcGatewayIP(ipn *net.IPNet) net.IP {
	nid := ipn.IP.Mask(ipn.Mask)
	return ip.NextIP(nid)
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
	file, err := os.OpenFile("/home/rise/info.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
}
