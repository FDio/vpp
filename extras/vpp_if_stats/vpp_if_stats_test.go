package main

import (
	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/examples/binapi/interfaces"
	"git.fd.io/govpp.git/examples/binapi/vpe"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

var (
	vppDetails = vpe.ShowVersionReply{
		Program: "vpe",
		Version: "18.10",
	}

	testSwIfIndex = uint32(0)
	testInterface = func() *vppInterface {
		return &vppInterface{
			SwInterfaceDetails: interfaces.SwInterfaceDetails{SwIfIndex: testSwIfIndex}, // TODO
			Stats:              interfaceStats{},                                        // TODO
		}
	}
	testInterfaces = func() *map[uint32]*vppInterface {
		return &map[uint32]*vppInterface{
			testInterface().SwIfIndex: testInterface(),
		}
	}

	r                 = rand.New(rand.NewSource(time.Now().UnixNano()))
	testCombinedStats = interfaceStats{
		TxBytes:   r.Uint64(),
		TxPackets: r.Uint64(),
		RxBytes:   r.Uint64(),
		RxPackets: r.Uint64(),
	}
	testCombinedStatsDump = []*adapter.StatEntry{
		{
			Name: "/if/tx",
			Type: adapter.CombinedCounterVector,
			Data: adapter.CombinedCounterStat{
				[]adapter.CombinedCounter{
					{
						Bytes:   adapter.Counter(testCombinedStats.TxBytes),
						Packets: adapter.Counter(testCombinedStats.TxPackets),
					},
				},
			},
		},
		{
			Name: "/if/rx",
			Type: adapter.CombinedCounterVector,
			Data: adapter.CombinedCounterStat{
				[]adapter.CombinedCounter{
					{
						Bytes:   adapter.Counter(testCombinedStats.RxBytes),
						Packets: adapter.Counter(testCombinedStats.RxPackets),
					},
				},
			},
		},
	}

	testSimpleStats = interfaceStats{
		TxErrors: r.Uint64(),
		RxErrors: r.Uint64(),
		Drops:    r.Uint64(),
		Punts:    r.Uint64(),
	}
	testSimpleStatsDump = []*adapter.StatEntry{
		{
			Name: "/if/tx-error",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.TxErrors)},
			},
		},
		{
			Name: "/if/rx-error",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.RxErrors)},
			},
		},
		{
			Name: "/if/drops",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter{adapter.Counter(testSimpleStats.Drops)},
			},
		},
		{
			Name: "/if/punt",
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

func TestVppIfStats_GetVppVersion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockChannel := NewMockChannel(mockCtrl)
	mockChannel.EXPECT().SendRequest(&vpe.ShowVersion{}).Return(&showDetailsContext{details: vppDetails})

	v := &VppConnector{api: mockChannel}
	err := v.GetVppVersion()
	assert.NoError(t, err, "GetVppVersion should not return an error")
	assert.Equal(t, vppDetails, v.VppDetails, "VPP details should be saved")
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

func TestVppIfStatsCommon_GetInterfaces(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	testContext := interfaceDumpContext{interfaces: []interfaces.SwInterfaceDetails{testInterface().SwInterfaceDetails}}
	mockChannel := NewMockChannel(mockCtrl)
	mockChannel.EXPECT().SendMultiRequest(&interfaces.SwInterfaceDump{}).Return(&testContext)

	v := &VppConnector{api: mockChannel}
	err := v.GetInterfaces()
	assert.NoError(t, err, "GetInterfaces should not return an error")
	assert.Len(t, v.Interfaces, len(testContext.interfaces), "All dumped interfaces should be saved")
	if len(testContext.interfaces) > 0 {
		assert.Equal(t, testContext.interfaces[0], v.Interfaces[testInterface().SwIfIndex].SwInterfaceDetails,
			"All dumped interface info should be saved")
	}
}

func TestVppIfStatsCommon_GetStatsForAllInterfacesNoStats(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockStatsAPI := NewMockStatsAPI(mockCtrl)
	mockStatsAPI.EXPECT().DumpStats("/if").Return([]*adapter.StatEntry{}, nil)

	v := &VppConnector{stats: mockStatsAPI, Interfaces: *testInterfaces()}
	err := v.GetStatsForAllInterfaces()
	assert.NoError(t, err, "GetStatsForAllInterfaces should not return an error")
	assert.Equal(t, interfaceStats{}, v.Interfaces[testSwIfIndex].Stats, "Stats should be empty")
}

func testStats(t *testing.T, statsDump *[]*adapter.StatEntry, expectedStats *interfaceStats) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockStatsAPI := NewMockStatsAPI(mockCtrl)
	mockStatsAPI.EXPECT().DumpStats("/if").Return(*statsDump, nil)

	v := &VppConnector{stats: mockStatsAPI, Interfaces: *testInterfaces()}
	err := v.GetStatsForAllInterfaces()
	assert.NoError(t, err, "GetStatsForAllInterfaces should not return an error")
	assert.Equal(t, *expectedStats, v.Interfaces[testSwIfIndex].Stats, "Collected and saved stats should match")
}

func TestVppIfStatsCommon_GetStatsForAllInterfacesCombinedStats(t *testing.T) {
	testStats(t, &testCombinedStatsDump, &testCombinedStats)
}

func TestVppIfStatsCommon_GetStatsForAllInterfacesSimpleStats(t *testing.T) {
	testStats(t, &testSimpleStatsDump, &testSimpleStats)
}
