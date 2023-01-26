package main

import (
	"fmt"
	"go.fd.io/govpp/binapi/ip_types"
	"math/rand"
	"time"
)

type AddressMap map[string]AddressWithPrefix

var addresses AddressMap = make(AddressMap)

func GenerateAddress() (AddressWithPrefix, error) {
	var ipPrefix AddressWithPrefix
	var err error

	for {
		rand.Seed(time.Now().UnixNano())
		address := fmt.Sprintf("10.10.10.%v/24", rand.Intn(255))
		ipPrefix, err = ip_types.ParseAddressWithPrefix(address)
		if err != nil {
			return AddressWithPrefix{}, err
		}
		if _, ok := addresses[address]; !ok {
			addresses[address] = ipPrefix
			break
		}
	}

	return ipPrefix, nil
}
