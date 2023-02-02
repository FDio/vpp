package main

import (
	"context"
	"os"

	"git.fd.io/govpp.git/api"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	ip_types "github.com/edwarnicke/govpp/binapi/ip_types"
	"github.com/edwarnicke/govpp/binapi/session"
	"github.com/edwarnicke/govpp/binapi/tapv2"
	"github.com/edwarnicke/vpphelper"
)

var (
	workDir, _ = os.Getwd()
)

type ConfFn func(context.Context, api.Connection) error

type Actions struct {
}

func (a *Actions) ConfigureTap(args []string) *ActionResult {
	var startup Stanza
	startup.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	ctx, cancel := newVppContext()
	defer cancel()
	con, vppErrCh := vpphelper.StartAndDialContext(ctx,
		vpphelper.WithRootDir(workDir),
		vpphelper.WithVppConfig(configTemplate+startup.ToString()))
	exitOnErrCh(ctx, cancel, vppErrCh)
	ifaceClient := interfaces.NewServiceClient(con)

	pref, err := ip_types.ParseIP4Prefix("10.10.10.2/24")
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("failed to parse ip4 address"))
	}
	createTapReply, err := tapv2.NewServiceClient(con).TapCreateV2(ctx, &tapv2.TapCreateV2{
		HostIfNameSet:    true,
		HostIfName:       "tap0",
		HostIP4PrefixSet: true,
		HostIP4Prefix:    ip_types.IP4AddressWithPrefix(pref),
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("failed to configure tap"))
	}
	ipPrefix, err := ip_types.ParseAddressWithPrefix("10.10.10.1/24")
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("parsing ip address failed"))
	}
	ipAddress := &interfaces.SwInterfaceAddDelAddress{
		IsAdd:     true,
		SwIfIndex: createTapReply.SwIfIndex,
		Prefix:    ipPrefix,
	}
	_, errx := ifaceClient.SwInterfaceAddDelAddress(ctx, ipAddress)
	if errx != nil {
		return NewActionResult(err, ActionResultWithDesc("configuring ip address failed"))
	}
	_, err = ifaceClient.SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: createTapReply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("failed to set interface state"))
	}
	_, err = session.NewServiceClient(con).SessionEnableDisable(ctx, &session.SessionEnableDisable{
		IsEnable: true,
	})
	if err != nil {
		return NewActionResult(err, ActionResultWithDesc("configuration failed"))
	}
	writeSyncFile(OkResult())
	<-ctx.Done()
	return nil
}
