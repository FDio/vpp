package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/edwarnicke/exechelper"
)

type AddressCounter = int
var ips []string
var chosenOctet int

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

	// Creates a file every time an IP is assigned: used to keep track of addresses in use.
	// If an address is not in use, 'counter' is then copied to 'chosenOctet' and it is used for the remaining tests.
	// Also checks host IP addresses.
	hostIps, _ := exechelper.CombinedOutput("ip a")
	counter := 10
	var address string

	for {
		if chosenOctet != 0{
			address = fmt.Sprintf("10.%v.%v.%v", chosenOctet, networkNumber, numberOfAddresses)
			file, err := os.Create(address)
			if err != nil{
				return "", errors.New("unable to create file: " + fmt.Sprint(err))
			}
			file.Close()
			break
		} else {
			address = fmt.Sprintf("10.%v.%v.%v", counter, networkNumber, numberOfAddresses)
			_, err := os.Stat(address)
			if err == nil || strings.Contains(string(hostIps), address) {
				counter++
			} else if os.IsNotExist(err){
				file, err := os.Create(address)
					if err != nil{
					return "", errors.New("unable to create file: " + fmt.Sprint(err))
					}
				file.Close()
				chosenOctet = counter
				break
			} else {
				return "", errors.New("an error occured while checking if a file exists: " + fmt.Sprint(err))
			}
		}
	}

	ips = append(ips, address)
	a.networks[networkNumber] = numberOfAddresses + 1

	return address + "/24", nil
}

func NewIp4AddressAllocator() *Ip4AddressAllocator {
	var ip4AddrAllocator = new(Ip4AddressAllocator)
	ip4AddrAllocator.networks = make(map[int]AddressCounter)
	ip4AddrAllocator.AddNetwork(0)
	return ip4AddrAllocator
}
