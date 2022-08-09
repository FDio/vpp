package main

import (
	"context"
	"fmt"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/vpphelper"
)

func configureProxyTcp(ifName0, ipAddr0, ifName1, ipAddr1 string) ConfFn {
	return func(ctx context.Context,
		vppConn api.Connection) error {

		_, err := configureAfPacket(ctx, vppConn, ifName0, ipAddr0)
		if err != nil {
			fmt.Printf("failed to create af packet: %v", err)
			return err
		}
		_, err = configureAfPacket(ctx, vppConn, ifName1, ipAddr1)
		if err != nil {
			fmt.Printf("failed to create af packet: %v", err)
			return err
		}
		return nil
	}
}

func TcVppProxy(args []string) *SyncResult {
	ctx, cancel := newVppContext()
	defer cancel()

	con, vppErrCh := vpphelper.StartAndDialContext(ctx, vpphelper.WithVppConfig(configTemplate))
	exitOnErrCh(ctx, cancel, vppErrCh)

	confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
	err := confFn(ctx, con)
	if err != nil {
		return NewResult(err, ResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}

func TcEnvoyProxy(args []string) *SyncResult {
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("evt_qs_memfd_seg").
		Append("event-queue-length 100000").Close()
	ctx, cancel := newVppContext()
	defer cancel()

	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(configTemplate+startup.ToString()),
		vpphelper.WithRootDir("/tmp/vpp-envoy"))
	exitOnErrCh(ctx, cancel, vppErrCh)

	confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
	err := confFn(ctx, con)
	if err != nil {
		return NewResult(err, ResultWithDesc("configuration failed"))
	}
	err0 := exechelper.Run("chmod 777 -R /tmp/vpp-envoy")
	if err0 != nil {
		return NewResult(err, ResultWithDesc("setting permissions failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}
