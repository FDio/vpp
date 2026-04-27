package main

import (
	_ "go.uber.org/mock/mockgen/model"
)

//go:generate go run go.uber.org/mock/mockgen -package main -destination statsmock.go go.fd.io/govpp/adapter StatsAPI
//go:generate go run go.uber.org/mock/mockgen -package main -destination apimock.go go.fd.io/govpp/api Channel
