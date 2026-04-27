package main

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/api"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/vpe"
	"go.uber.org/mock/gomock"
)

var (
	vppDetails = vpe.ShowVersionReply{
		Program: "vpe",
		Version: "18.10",
	}

	testSwIfIndex = uint32(0)
	testInterface = func() *vppInterface {
		return &vppInterface{
			SwInterfaceDetails: interfaces.SwInterfaceDetails{
				SwIfIndex: interface_types.InterfaceIndex(testSwIfIndex),
			}, // TODO
			Stats: interfaceStats{}, // TODO
		}
	}
	testInterfaces = func() []*vppInterface {
		return []*vppInterface{
			testInterface(),
		}
	}

	r                 = rand.New(rand.NewSource(time.Now().UnixNano()))
	testCombinedStats = interfaceStats{
		TxBytes:   r.Uint64(),
		TxPackets: r.Uint64(),
		RxBytes:   r.Uint64(),
		RxPackets: r.Uint64(),
	}
	testCombinedStatsDump = []adapter.StatEntry{
		{
			StatIdentifier: adapter.StatIdentifier{
				Name: []byte("/if/tx"),
			},
			Type: adapter.CombinedCounterVector,
			Data: adapter.CombinedCounterStat{
				[]adapter.CombinedCounter{{
					testCombinedStats.TxPackets,
					testCombinedStats.TxBytes,
				}},
			},
		},
		{
			StatIdentifier: adapter.StatIdentifier{
				Name: []byte("/if/rx"),
			},
			Type: adapter.CombinedCounterVector,
			Data: adapter.CombinedCounterStat{
				[]adapter.CombinedCounter{{
					testCombinedStats.RxPackets,
					testCombinedStats.RxBytes,
				}},
			},
		},
	}

	testSimpleStats = interfaceStats{
		TxErrors: r.Uint64(),
		RxErrors: r.Uint64(),
		Drops:    r.Uint64(),
		Punts:    r.Uint64(),
	}
	testSimpleStatsDump = []adapter.StatEntry{
		{
			StatIdentifier: adapter.StatIdentifier{
				Name: []byte("/if/tx-error"),
			},
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.TxErrors)},
			},
		},
		{
			StatIdentifier: adapter.StatIdentifier{
				Name: []byte("/if/rx-error"),
			},
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.RxErrors)},
			},
		},
		{
			StatIdentifier: adapter.StatIdentifier{
				Name: []byte("/if/drops"),
			},
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.Drops)},
			},
		},
		{
			StatIdentifier: adapter.StatIdentifier{
				Name: []byte("/if/punt"),
			},
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.Punts)},
			},
		},
	}
)

type showDetailsContext struct {
	details vpe.ShowVersionReply
}

func (ctx *showDetailsContext) ReceiveReply(msg api.Message) (err error) {
	*(msg.(*vpe.ShowVersionReply)) = vppDetails
	return nil
}

type interfaceDumpContext struct {
	interfaces   []interfaces.SwInterfaceDetails
	currentIndex int
}

func (ctx *interfaceDumpContext) ReceiveReply(msg api.Message) (lastReplyReceived bool, err error) {
	stop := ctx.currentIndex >= len(ctx.interfaces)
	if !stop {
		*(msg.(*interfaces.SwInterfaceDetails)) = ctx.interfaces[ctx.currentIndex]
		ctx.currentIndex++
	}
	return stop, nil
}

func TestVppIfStats_GetVppVersion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockChannel := NewMockChannel(mockCtrl)
	mockChannel.EXPECT().SendRequest(&vpe.ShowVersion{}).Return(&showDetailsContext{details: vppDetails})

	v := vppConnector{api: mockChannel}
	err := v.getVppVersion()
	assert.NoError(t, err, "GetVppVersion should not return an error")
	assert.Equal(t, vppDetails, v.VppDetails, "VPP details should be saved")
}

func TestVppIfStats_GetInterfaces(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	testContext := interfaceDumpContext{interfaces: []interfaces.SwInterfaceDetails{testInterface().SwInterfaceDetails}}
	mockChannel := NewMockChannel(mockCtrl)
	mockChannel.EXPECT().SendMultiRequest(&interfaces.SwInterfaceDump{}).Return(&testContext)

	v := vppConnector{api: mockChannel}
	err := v.getInterfaces()
	assert.NoError(t, err, "GetInterfaces should not return an error")
	assert.Len(t, v.Interfaces, len(testContext.interfaces), "All dumped interfaces should be saved")
	if len(testContext.interfaces) > 0 {
		assert.Equal(t, testContext.interfaces[0], v.Interfaces[testInterface().SwIfIndex].SwInterfaceDetails,
			"All dumped interface info should be saved")
	}
}

func TestVppIfStats_GetStatsForAllInterfacesNoStats(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockStatsAPI := NewMockStatsAPI(mockCtrl)
	mockStatsAPI.EXPECT().DumpStats("/if").Return([]adapter.StatEntry{}, nil)

	v := vppConnector{stats: mockStatsAPI, Interfaces: testInterfaces()}
	err := v.getStatsForAllInterfaces()
	assert.NoError(t, err, "GetStatsForAllInterfaces should not return an error")
	assert.Equal(t, interfaceStats{}, v.Interfaces[testSwIfIndex].Stats, "Stats should be empty")
}

func testStats(t *testing.T, statsDump *[]adapter.StatEntry, expectedStats *interfaceStats) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockStatsAPI := NewMockStatsAPI(mockCtrl)
	mockStatsAPI.EXPECT().DumpStats("/if").Return(*statsDump, nil)

	v := vppConnector{stats: mockStatsAPI, Interfaces: testInterfaces()}
	err := v.getStatsForAllInterfaces()
	assert.NoError(t, err, "GetStatsForAllInterfaces should not return an error")
	assert.Equal(t, *expectedStats, v.Interfaces[testSwIfIndex].Stats, "Collected and saved stats should match")
}

func TestVppIfStats_GetStatsForAllInterfacesCombinedStats(t *testing.T) {
	testStats(t, &testCombinedStatsDump, &testCombinedStats)
}

func TestVppIfStats_GetStatsForAllInterfacesSimpleStats(t *testing.T) {
	testStats(t, &testSimpleStatsDump, &testSimpleStats)
}
