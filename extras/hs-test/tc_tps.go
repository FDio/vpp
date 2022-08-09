package main

import (
	"github.com/edwarnicke/govpp/binapi/session"
	"github.com/edwarnicke/vpphelper"
)

func TcHttpTps(args []string) *SyncResult {
	ctx, cancel := newVppContext()
	defer cancel()
	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithVppConfig(configTemplate))
	exitOnErrCh(ctx, cancel, vppErrCh)

	confFn := configureProxyTcp("vpp0", "10.0.0.2/24", "vpp1", "10.0.1.2/24")
	err := confFn(ctx, con)
	if err != nil {
		return NewResult(err, ResultWithDesc("configuration failed"))
	}

	_, err = session.NewServiceClient(con).SessionEnableDisable(ctx, &session.SessionEnableDisable{
		IsEnable: true,
	})
	if err != nil {
		return NewResult(err, ResultWithDesc("configuration failed"))
	}
	Vppcli("", "http tps uri tcp://0.0.0.0/8080")
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}
