package main

import "fmt"

type AddressCounter = int

type Ip4AddressAllocator struct {
	networks map[int]AddressCounter
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

	address := fmt.Sprintf("10.10.%v.%v/24", networkNumber, numberOfAddresses)
	a.networks[networkNumber] = numberOfAddresses + 1

	return address, nil
}

func NewIp4AddressAllocator() *Ip4AddressAllocator {
	var ip4AddrAllocator = new(Ip4AddressAllocator)
	ip4AddrAllocator.networks = make(map[int]AddressCounter)
	ip4AddrAllocator.AddNetwork(0)
	return ip4AddrAllocator
}
