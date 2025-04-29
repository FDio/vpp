package hst

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/edwarnicke/exechelper"
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

// Creates a file every time an IP is assigned: used to keep track of addresses in use.
// If an address is not in use, 'counter' is then copied to 'chosenOctet' and it is used for the remaining tests.
// Also checks host IP addresses.
func (a *Ip4AddressAllocator) createIpAddress(networkNumber int, numberOfAddresses int) (string, error) {
	hostIps, _ := exechelper.CombinedOutput("ip a")
	counter := 10
	var address string

	for {
		if a.chosenOctet != 0 {
			address = fmt.Sprintf("10.%v.%v.%v", a.chosenOctet, networkNumber, numberOfAddresses)
			file, err := os.Create(address)
			if err != nil {
				return "", errors.New("unable to create file: " + fmt.Sprint(err))
			}
			file.Close()
			break
		} else {
			address = fmt.Sprintf("10.%v.%v.%v", counter, networkNumber, numberOfAddresses)
			_, err := os.Stat(address)
			if err == nil || strings.Contains(string(hostIps), address) {
				counter++
			} else if os.IsNotExist(err) {
				file, err := os.Create(address)
				if err != nil {
					return "", errors.New("unable to create file: " + fmt.Sprint(err))
				}
				file.Close()
				a.chosenOctet = counter
				break
			} else {
				return "", errors.New("an error occurred while checking if a file exists: " + fmt.Sprint(err))
			}
		}
	}

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

	return address + "/8", err
}

func (a *Ip6AddressAllocator) createIpAddress(networkNumber int, numberOfAddresses int) (string, error) {
	hostIps, _ := exechelper.CombinedOutput("ip -6 a")
	counter := 0xAAAA
	var address string

	for {
		if a.chosenSegment != "" {
			address = fmt.Sprintf("fd00:0000:%s:%x::%x", a.chosenSegment, networkNumber, numberOfAddresses)
			file, err := os.Create(address)
			if err != nil {
				return "", errors.New("unable to create file: " + fmt.Sprint(err))
			}
			file.Close()
			break
		} else {
			address = fmt.Sprintf("fd00:0000:%x:%x::%x", counter, networkNumber, numberOfAddresses)
			_, err := os.Stat(address)
			if err == nil || strings.Contains(string(hostIps), address) {
				counter++
			} else if os.IsNotExist(err) {
				file, err := os.Create(address)
				if err != nil {
					return "", errors.New("unable to create file: " + fmt.Sprint(err))
				}
				file.Close()
				a.chosenSegment = fmt.Sprintf("%x", counter)
				break
			} else {
				return "", errors.New("an error occurred while checking if a file exists: " + fmt.Sprint(err))
			}
		}
	}

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
