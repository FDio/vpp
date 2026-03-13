package hst

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
)

type AddressCounter = int

type Ip4AddressAllocator struct {
	networks    map[int]AddressCounter
	chosenOctet int
	assignedIps []string
}

func (a *Ip4AddressAllocator) AddNetwork(networkNumber int) {
	a.networks[networkNumber] = 1
}

func (a *Ip4AddressAllocator) NewIp4InterfaceAddress(inputNetworkNumber ...int) (string, error) {
	var networkNumber int = 0
	if len(inputNetworkNumber) > 0 {
		networkNumber = inputNetworkNumber[0]
	}

	if _, ok := a.networks[networkNumber]; !ok {
		a.AddNetwork(networkNumber)
	}

	numberOfAddresses := a.networks[networkNumber]

	if numberOfAddresses == 254 {
		return "", fmt.Errorf("no available IPv4 addresses")
	}

	address, err := a.createIpAddress(networkNumber, numberOfAddresses)

	a.networks[networkNumber] = numberOfAddresses + 1

	return address + "/24", err
}

func (a *Ip4AddressAllocator) createIpAddress(networkNumber int, numberOfAddresses int) (string, error) {
	// "GinkgoParallelProcess()+9" so the first process uses 10.10.x.y
	address := fmt.Sprintf("10.%v.%v.%v", GinkgoParallelProcess()+9, networkNumber, numberOfAddresses)

	a.assignedIps = append(a.assignedIps, address)
	return address, nil
}

func (a *Ip4AddressAllocator) DeleteIpAddresses() {
	for ip := range a.assignedIps {
		os.Remove(a.assignedIps[ip])
	}
}

func NewIp4AddressAllocator() *Ip4AddressAllocator {
	var ip4AddrAllocator = new(Ip4AddressAllocator)
	ip4AddrAllocator.networks = make(map[int]AddressCounter)
	ip4AddrAllocator.AddNetwork(0)
	return ip4AddrAllocator
}

type Ip6AddressAllocator struct {
	networks      map[int]AddressCounter
	chosenSegment string
	assignedIps   []string
}

func (a *Ip6AddressAllocator) AddNetwork(networkNumber int) {
	a.networks[networkNumber] = 1
}

func (a *Ip6AddressAllocator) NewIp6InterfaceAddress(inputNetworkNumber ...int) (string, error) {
	var networkNumber int = 0
	if len(inputNetworkNumber) > 0 {
		networkNumber = inputNetworkNumber[0]
	}

	if _, ok := a.networks[networkNumber]; !ok {
		a.AddNetwork(networkNumber)
	}

	numberOfAddresses := a.networks[networkNumber]

	if numberOfAddresses == 65535 {
		return "", fmt.Errorf("no available IPv6 addresses")
	}

	address, err := a.createIpAddress(networkNumber, numberOfAddresses)

	a.networks[networkNumber] = numberOfAddresses + 1

	return address + "/64", err
}

func (a *Ip6AddressAllocator) createIpAddress(networkNumber int, numberOfAddresses int) (string, error) {
	address := fmt.Sprintf("fd00:0:%x:%x::%x", GinkgoParallelProcess(), networkNumber, numberOfAddresses)

	a.assignedIps = append(a.assignedIps, address)
	return address, nil
}

func (a *Ip6AddressAllocator) DeleteIpAddresses() {
	for ip := range a.assignedIps {
		os.Remove(a.assignedIps[ip])
	}
}

func NewIp6AddressAllocator() *Ip6AddressAllocator {
	var ip6AddrAllocator = new(Ip6AddressAllocator)
	ip6AddrAllocator.networks = make(map[int]AddressCounter)
	ip6AddrAllocator.AddNetwork(0)
	return ip6AddrAllocator
}
