package main

import (
	"fmt"
	"go.fd.io/govpp/binapi/ip_types"
	"math/rand"
	"time"
)

type AddressMap map[string]ip_types.AddressWithPrefix

var addresses AddressMap = make(AddressMap)

func GenerateAddress() (ip_types.AddressWithPrefix, error) {
	var ipPrefix ip_types.AddressWithPrefix
	var err error

	for {
		rand.Seed(time.Now().UnixNano())
		address := fmt.Sprintf("10.10.10.%v/24", rand.Intn(255))
		ipPrefix, err = ip_types.ParseAddressWithPrefix(address)
		if err != nil {
			return ip_types.AddressWithPrefix{}, err
		}
		if _, ok := addresses[address]; !ok {
			addresses[address] = ipPrefix
			break
		}
	}

	return ipPrefix, nil
}
