package main

import (
	"context"
	"fmt"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/vpphelper"
)

func Tc2Veths(args []string) *SyncResult {
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	ctx, cancel := newVppContext()
	defer cancel()
	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(configTemplate+startup.ToString()),
		vpphelper.WithRootDir(fmt.Sprintf("/tmp/%s", args[1])))
	exitOnErrCh(ctx, cancel, vppErrCh)

	var fn func(context.Context, api.Connection) error
	if args[2] == "srv" {
		fn = configure2vethsTopo("vppsrv", "10.10.10.1/24", "1", 1)
	} else {
		fn = configure2vethsTopo("vppcln", "10.10.10.2/24", "2", 2)
	}
	err := fn(ctx, con)
	if err != nil {
		return NewResult(err, ResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}
