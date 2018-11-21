package vppifstats

import (
	"git.fd.io/govpp.git/examples/bin_api/vpe"
	"github.com/golang/mock/gomock"
	"testing"
	"github.com/stretchr/testify/assert"
	"git.fd.io/govpp.git/examples/bin_api/interfaces"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/adapter"
	"math/rand"
	"time"
	)


var (
	vppDetails = vpe.ShowVersionReply{
		Program: []byte("vpe"),
		Version: []byte("18.10"),
	}

	testSwIfIndex = uint32(0)
	testInterface = func() *VppInterface {
		return &VppInterface {
			SwInterfaceDetails: interfaces.SwInterfaceDetails{SwIfIndex: testSwIfIndex},  // TODO
			Stats: InterfaceStats{},  // TODO
		}
	}
	testInterfaces = func() *map[uint32]*VppInterface {
		return &map[uint32]*VppInterface {
			testSwIfIndex: testInterface(),
		}
	}

	r = rand.New(rand.NewSource(time.Now().UnixNano()))
	testCombinedStats = InterfaceStats{
		TxBytes: r.Uint64(),
		TxPackets: r.Uint64(),
		RxBytes: r.Uint64(),
		RxPackets: r.Uint64(),
	}
	testCombinedStatsDump = []*adapter.StatEntry{
		{
			Name: "/if/tx",
			Type: adapter.CombinedCounterVector,
			Data: adapter.CombinedCounterStat{
				[]adapter.CombinedCounter{
					{
						Bytes: adapter.Counter(testCombinedStats.TxBytes),
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
						Bytes: adapter.Counter(testCombinedStats.RxBytes),
						Packets: adapter.Counter(testCombinedStats.RxPackets),
					},
				},
			},
		},
	}

	testSimpleStats = InterfaceStats{
		TxErrors: r.Uint64(),
		RxErrors: r.Uint64(),
		Drops: r.Uint64(),
		Punts: r.Uint64(),
	}
	testSimpleStatsDump = []*adapter.StatEntry{
		{
			Name: "/if/tx-error",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter {adapter.Counter(testSimpleStats.TxErrors)},
			},
		},
		{
			Name: "/if/rx-error",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter {adapter.Counter(testSimpleStats.RxErrors)},
			},
		},
		{
			Name: "/if/drops",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter {adapter.Counter(testSimpleStats.Drops)},
			},
		},
		{
			Name: "/if/punt",
			Type: adapter.SimpleCounterVector,
			Data: adapter.SimpleCounterStat{
				[]adapter.Counter {adapter.Counter(testSimpleStats.Punts)},
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
	interfaces []interfaces.SwInterfaceDetails
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

	v := VppIfStats{api: mockChannel}
	err := v.GetVppVersion()
	assert.NoError(t, err, "GetVppVersion should not return an error")
	assert.Equal(t, vppDetails, v.VppDetails, "VPP details should be saved")
}

func TestVppIfStats_GetInterfaces(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	testContext := interfaceDumpContext{interfaces: []interfaces.SwInterfaceDetails{testInterface().SwInterfaceDetails}}
	mockChannel := NewMockChannel(mockCtrl)
	mockChannel.EXPECT().SendMultiRequest(&interfaces.SwInterfaceDump{}).Return(&testContext)

	v := VppIfStats{api: mockChannel}
	err := v.GetInterfaces()
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
	mockStatsAPI.EXPECT().DumpStats("/if").Return([]*adapter.StatEntry{}, nil)

	v := VppIfStats{stats: mockStatsAPI, Interfaces: *testInterfaces()}
	err := v.GetStatsForAllInterfaces()
	assert.NoError(t, err, "GetStatsForAllInterfaces should not return an error")
	assert.Equal(t, InterfaceStats{}, v.Interfaces[testSwIfIndex].Stats, "Stats should be empty")
}

func testStats(t *testing.T, statsDump *[]*adapter.StatEntry, expectedStats *InterfaceStats) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockStatsAPI := NewMockStatsAPI(mockCtrl)
	mockStatsAPI.EXPECT().DumpStats("/if").Return(*statsDump, nil)

	v := VppIfStats{stats: mockStatsAPI, Interfaces: *testInterfaces()}
	err := v.GetStatsForAllInterfaces()
	assert.NoError(t, err, "GetStatsForAllInterfaces should not return an error")
	assert.Equal(t, *expectedStats, v.Interfaces[testSwIfIndex].Stats, "Collected and saved stats should match")
}

func TestVppIfStats_GetStatsForAllInterfacesCombinedStats(t *testing.T) {
	testStats(t, &testCombinedStatsDump, &testCombinedStats)
}

func TestVppIfStats_GetStatsForAllInterfacesSimpleStats(t *testing.T) {
	testStats(t, &testSimpleStatsDump, &testSimpleStats)
}