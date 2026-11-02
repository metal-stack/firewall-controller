package controllers

import (
	"errors"
	"fmt"
	"os"

	"github.com/metal-stack/api/go/enum"
	apiv2 "github.com/metal-stack/api/go/metalstack/api/v2"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/metal-lib/pkg/pointer"

	osnet "github.com/metal-stack/os-installer/pkg/network"
)

func toMachineAllocation(f *firewallv2.Firewall) (*apiv2.MachineAllocation, string, error) {
	var vpn *apiv2.MachineVPN
	if f.Status.VPN != nil {
		vpn = &apiv2.MachineVPN{
			// Authkey is omitted for security reasons
			ControlPlaneAddress: pointer.SafeDeref(&f.Status.VPN.ControlPlaneAddress),
		}
	}

	var networks []*apiv2.MachineNetwork
	for _, nw := range f.Status.FirewallNetworks {

		natType := apiv2.NATType_NAT_TYPE_NONE
		if nw.Nat != nil && *nw.Nat {
			natType = apiv2.NATType_NAT_TYPE_IPV4_MASQUERADE
		}

		networkType, err := enum.GetEnum[apiv2.NetworkType](pointer.SafeDeref(nw.NetworkTypeV2))
		if err != nil {
			return nil, "", err
		}

		networks = append(networks, &apiv2.MachineNetwork{
			Network:             pointer.SafeDeref(nw.NetworkID),
			Prefixes:            nw.Prefixes,
			DestinationPrefixes: nw.DestinationPrefixes,
			Ips:                 nw.IPs,
			Vrf:                 uint64(pointer.SafeDeref(nw.Vrf)),
			Asn:                 uint32(pointer.SafeDeref(nw.ASN)),
			Project:             nw.Project,
			NatType:             natType,
			NetworkType:         networkType,
		})
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, "", err
	}
	machineAllocation := &apiv2.MachineAllocation{
		Project:        f.Spec.Project,
		Hostname:       hostname,
		AllocationType: apiv2.MachineAllocationType_MACHINE_ALLOCATION_TYPE_FIREWALL,
		Networks:       networks,
		// TODO the following properties are not required during reconciliation
		// FirewallRules:  firewallRules,
		// DnsServers:     dnsservers,
		// NtpServers:     ntpservers,
		Vpn: vpn,
	}

	defaultRouteNetwork, err := osnet.New(machineAllocation).GetDefaultRouteNetwork()
	if err != nil {
		return nil, "", fmt.Errorf("unable to get a default route network: %w", err)
	}
	if len(defaultRouteNetwork.Ips) == 0 {
		return nil, "", errors.New("default route network does not have ips")
	}

	return machineAllocation, defaultRouteNetwork.Ips[0], nil
}
