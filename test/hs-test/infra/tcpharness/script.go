/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package tcpharness

import (
	"fmt"
	"sort"
)

const nfQueueScriptTraceCapacity = 128

type DataSegment struct {
	Seq uint32
	End uint32
}

type NFQueueAckState struct {
	SeqEnd  uint32
	Ack     uint32
	Valid   bool
	SrcPort uint16
	DstPort uint16
}

type nfQueueRole uint8

const (
	nfQueueRoleIngress nfQueueRole = iota
	nfQueueRoleEgress
)

type NFQueueScriptStage uint8

const (
	NFQueueScriptStageWaitingInitial NFQueueScriptStage = iota
	NFQueueScriptStageWaitingPartial
	NFQueueScriptStageDone
)

type nfQueueScriptTrigger uint8

const (
	nfQueueScriptTriggerInitialHolesReady nfQueueScriptTrigger = iota
	nfQueueScriptTriggerRetransmitOfDroppedSeqObserved
)

type nfQueueAckQueueDisposition uint8

const (
	nfQueueAckQueueDispositionNone nfQueueAckQueueDisposition = iota
	nfQueueAckQueueDispositionKeepQueued
	nfQueueAckQueueDispositionReplayQueued
	nfQueueAckQueueDispositionDiscardQueued
)

type NFQueueScriptStep struct {
	trigger             nfQueueScriptTrigger
	holeCount           int
	injectCount         int
	stopIngressDrops    bool
	ackQueueDisposition nfQueueAckQueueDisposition
	advanceToDone       bool
}

type NFQueueScriptStepOption func(*NFQueueScriptStep)

func InitialHolesSackStep(holeCount, injectCount int,
	opts ...NFQueueScriptStepOption) NFQueueScriptStep {
	step := NFQueueScriptStep{
		trigger:          nfQueueScriptTriggerInitialHolesReady,
		holeCount:        holeCount,
		injectCount:      injectCount,
		stopIngressDrops: true,
	}
	return applyNFQueueScriptStepOptions(step, opts...)
}

func RetransmitPartialAckStep(injectCount int,
	opts ...NFQueueScriptStepOption) NFQueueScriptStep {
	step := NFQueueScriptStep{
		trigger:     nfQueueScriptTriggerRetransmitOfDroppedSeqObserved,
		injectCount: injectCount,
	}
	return applyNFQueueScriptStepOptions(step, opts...)
}

func KeepQueuedAcks() NFQueueScriptStepOption {
	return func(step *NFQueueScriptStep) {
		step.ackQueueDisposition = nfQueueAckQueueDispositionKeepQueued
	}
}

func DiscardQueuedAcks() NFQueueScriptStepOption {
	return func(step *NFQueueScriptStep) {
		step.ackQueueDisposition = nfQueueAckQueueDispositionDiscardQueued
	}
}

func ReplayQueuedAcks() NFQueueScriptStepOption {
	return func(step *NFQueueScriptStep) {
		step.ackQueueDisposition = nfQueueAckQueueDispositionReplayQueued
	}
}

func AdvanceScriptToDone() NFQueueScriptStepOption {
	return func(step *NFQueueScriptStep) {
		step.advanceToDone = true
	}
}

func applyNFQueueScriptStepOptions(step NFQueueScriptStep,
	opts ...NFQueueScriptStepOption) NFQueueScriptStep {
	for _, opt := range opts {
		opt(&step)
	}
	return step
}

type NFQueueScriptConfig struct {
	dropDataPacketIndices []uint32
	steps                 []NFQueueScriptStep
}

func NFQueueScript(dropDataPacketIndices []uint32,
	steps ...NFQueueScriptStep) NFQueueScriptConfig {
	return NFQueueScriptConfig{
		dropDataPacketIndices: append([]uint32(nil), dropDataPacketIndices...),
		steps:                 cloneNFQueueScriptSteps(steps),
	}
}

func (cfg NFQueueScriptConfig) DropDataPacketIndices() []uint32 {
	return append([]uint32(nil), cfg.dropDataPacketIndices...)
}

func (cfg NFQueueScriptConfig) WithDefaults() NFQueueScriptConfig {
	cfg = cloneNFQueueScriptConfig(cfg)
	for i := range cfg.steps {
		if cfg.steps[i].holeCount == 0 {
			cfg.steps[i].holeCount = len(cfg.dropDataPacketIndices)
		}
		if cfg.steps[i].injectCount == 0 {
			cfg.steps[i].injectCount = 1
		}
	}
	return cfg
}

type NFQueueScriptTraceEventKind uint8

const (
	NFQueueScriptTraceDataSegmentObserved NFQueueScriptTraceEventKind = iota
	NFQueueScriptTraceOriginalDataDrop
	NFQueueScriptTraceRetransmitObserved
	NFQueueScriptTraceNaturalAckQueued
	NFQueueScriptTraceNaturalAckDropped
	NFQueueScriptTraceSyntheticAckInjected
	NFQueueScriptTraceQueuedAckReplayed
	NFQueueScriptTraceQueuedAckDiscarded
	NFQueueScriptTraceStageAdvanced
	NFQueueScriptTraceGateReleased
)

type NFQueueScriptTraceEntry struct {
	Kind   NFQueueScriptTraceEventKind
	Stage  NFQueueScriptStage
	Seq    uint32
	Ack    uint32
	Detail string
}

type NFQueueScriptStats struct {
	Stage                     NFQueueScriptStage
	OriginalDropCount         uint64
	RetransmitTriggerCount    uint64
	NaturalAckQueuedCount     uint64
	NaturalAckDroppedCount    uint64
	SyntheticAckInjectedCount uint64
	QueuedAckReplayedCount    uint64
	QueuedAckDiscardedCount   uint64
	LastErrorText             string
	ResolvedDroppedSeqs       []uint32
	ResolvedSegments          []DataSegment
}

type nfQueueInjection struct {
	Ack        uint32
	Window     uint16
	Count      int
	SackBlocks []TcpTestEndpointSackBlock
}

type nfQueueScriptEvent struct {
	Role           nfQueueRole
	Packet         PcapIPv4TCPPacket
	OriginalDrop   bool
	RetransmitSeen bool
}

type nfQueueScriptAction struct {
	QueueNaturalAck  bool
	StopIngressDrops bool
	QueueDisposition nfQueueAckQueueDisposition
	Injections       []nfQueueInjection
}

type nfQueueScriptState struct {
	cfg                 NFQueueScriptConfig
	steps               []NFQueueScriptStep
	stage               NFQueueScriptStage
	currentStep         int
	gateEnabled         bool
	retransmitLatched   bool
	pendingQueuedAcks   int
	dataSegments        map[uint32]uint32
	droppedOriginalSeq  map[uint32]struct{}
	resolvedDroppedSeqs []uint32
	resolvedSegments    []DataSegment
	ackState            NFQueueAckState
	stats               NFQueueScriptStats
	trace               []NFQueueScriptTraceEntry
}

func newNFQueueScriptState(cfg NFQueueScriptConfig) *nfQueueScriptState {
	state := &nfQueueScriptState{
		cfg:                cloneNFQueueScriptConfig(cfg),
		stage:              NFQueueScriptStageWaitingInitial,
		gateEnabled:        true,
		dataSegments:       make(map[uint32]uint32),
		droppedOriginalSeq: make(map[uint32]struct{}),
	}
	state.steps = cloneNFQueueScriptSteps(state.cfg.steps)
	state.stats.Stage = state.stage
	return state
}

func (s *nfQueueScriptState) DroppedOriginalSeqSeen(seq uint32) bool {
	_, ok := s.droppedOriginalSeq[seq]
	return ok
}

func (s *nfQueueScriptState) Stats() NFQueueScriptStats {
	stats := s.stats
	stats.Stage = s.stage
	stats.ResolvedDroppedSeqs = append([]uint32(nil), s.resolvedDroppedSeqs...)
	stats.ResolvedSegments = append([]DataSegment(nil), s.resolvedSegments...)
	return stats
}

func (s *nfQueueScriptState) Trace() []NFQueueScriptTraceEntry {
	return append([]NFQueueScriptTraceEntry(nil), s.trace...)
}

func (s *nfQueueScriptState) SetLastErrorText(text string) {
	s.setLastErrorText(text)
}

func (s *nfQueueScriptState) RecordNaturalAckQueued(packet PcapIPv4TCPPacket) {
	s.stats.NaturalAckQueuedCount++
	s.pendingQueuedAcks++
	s.appendTrace(NFQueueScriptTraceEntry{
		Kind:   NFQueueScriptTraceNaturalAckQueued,
		Stage:  s.stage,
		Seq:    packet.Seq,
		Ack:    packet.Ack,
		Detail: "natural ACK queued by NFQUEUE adapter",
	})
}

func (s *nfQueueScriptState) RecordSyntheticAckInjected(spec nfQueueInjection) {
	if spec.Count > 0 {
		s.stats.SyntheticAckInjectedCount += uint64(spec.Count)
	}
	s.appendTrace(NFQueueScriptTraceEntry{
		Kind:   NFQueueScriptTraceSyntheticAckInjected,
		Stage:  s.stage,
		Ack:    spec.Ack,
		Detail: fmt.Sprintf("count=%d sack_blocks=%d", spec.Count, len(spec.SackBlocks)),
	})
}

func (s *nfQueueScriptState) RecordQueuedAckReplayed(packet PcapIPv4TCPPacket) {
	if s.pendingQueuedAcks > 0 {
		s.pendingQueuedAcks--
	}
	s.stats.QueuedAckReplayedCount++
	s.appendTrace(NFQueueScriptTraceEntry{
		Kind:   NFQueueScriptTraceQueuedAckReplayed,
		Stage:  s.stage,
		Seq:    packet.Seq,
		Ack:    packet.Ack,
		Detail: "queued natural ACK replayed",
	})
}

func (s *nfQueueScriptState) RecordQueuedAckDiscarded(packet PcapIPv4TCPPacket) {
	if s.pendingQueuedAcks > 0 {
		s.pendingQueuedAcks--
	}
	s.stats.QueuedAckDiscardedCount++
	s.appendTrace(NFQueueScriptTraceEntry{
		Kind:   NFQueueScriptTraceQueuedAckDiscarded,
		Stage:  s.stage,
		Seq:    packet.Seq,
		Ack:    packet.Ack,
		Detail: "queued natural ACK discarded",
	})
}

func (s *nfQueueScriptState) ApplyEvent(event nfQueueScriptEvent) nfQueueScriptAction {
	s.observeEvent(event)

	action := nfQueueScriptAction{}
	if s.shouldGateNaturalAck(event) {
		action.QueueNaturalAck = true
		s.stats.NaturalAckDroppedCount++
		s.appendTrace(NFQueueScriptTraceEntry{
			Kind:   NFQueueScriptTraceNaturalAckDropped,
			Stage:  s.stage,
			Seq:    event.Packet.Seq,
			Ack:    event.Packet.Ack,
			Detail: "natural ACK suppressed by script gate",
		})
	}

	stepAction := s.applyCurrentStep()
	action.StopIngressDrops = stepAction.StopIngressDrops
	action.QueueDisposition = stepAction.QueueDisposition
	action.Injections = append(action.Injections, stepAction.Injections...)
	action.QueueNaturalAck = action.QueueNaturalAck || stepAction.QueueNaturalAck

	return action
}

func (s *nfQueueScriptState) observeEvent(event nfQueueScriptEvent) {
	if event.Packet.PayloadLen > 0 {
		end := event.Packet.SeqEnd()
		if prevEnd, ok := s.dataSegments[event.Packet.Seq]; !ok || end > prevEnd {
			s.dataSegments[event.Packet.Seq] = end
			s.appendTrace(NFQueueScriptTraceEntry{
				Kind:   NFQueueScriptTraceDataSegmentObserved,
				Stage:  s.stage,
				Seq:    event.Packet.Seq,
				Ack:    event.Packet.Ack,
				Detail: fmt.Sprintf("segment end=%d payload=%d", end, event.Packet.PayloadLen),
			})
		}
	}

	if event.Role == nfQueueRoleEgress && event.Packet.Flags&tcpFlagAck != 0 {
		seqEnd := event.Packet.SeqEnd()
		if !s.ackState.Valid || seqEnd > s.ackState.SeqEnd {
			s.ackState.SeqEnd = seqEnd
		}
		if !s.ackState.Valid || event.Packet.Ack > s.ackState.Ack {
			s.ackState.Ack = event.Packet.Ack
		}
		s.ackState.SrcPort = event.Packet.SrcPort
		s.ackState.DstPort = event.Packet.DstPort
		s.ackState.Valid = true
	}

	if event.OriginalDrop {
		if _, ok := s.droppedOriginalSeq[event.Packet.Seq]; !ok {
			s.droppedOriginalSeq[event.Packet.Seq] = struct{}{}
			s.stats.OriginalDropCount++
			s.appendTrace(NFQueueScriptTraceEntry{
				Kind:   NFQueueScriptTraceOriginalDataDrop,
				Stage:  s.stage,
				Seq:    event.Packet.Seq,
				Ack:    event.Packet.Ack,
				Detail: "original dropped data segment recorded",
			})
		}
	}

	if event.RetransmitSeen {
		s.retransmitLatched = true
		s.stats.RetransmitTriggerCount++
		s.appendTrace(NFQueueScriptTraceEntry{
			Kind:   NFQueueScriptTraceRetransmitObserved,
			Stage:  s.stage,
			Seq:    event.Packet.Seq,
			Ack:    event.Packet.Ack,
			Detail: "retransmit of previously dropped sequence observed",
		})
	}
}

func (s *nfQueueScriptState) shouldGateNaturalAck(event nfQueueScriptEvent) bool {
	return event.Role == nfQueueRoleEgress &&
		s.gateEnabled &&
		event.Packet.IsAckOnly() &&
		!event.Packet.IsSyntheticAck()
}

func (s *nfQueueScriptState) applyCurrentStep() nfQueueScriptAction {
	if s.stage == NFQueueScriptStageDone || s.currentStep >= len(s.steps) {
		return nfQueueScriptAction{}
	}

	step := s.steps[s.currentStep]
	injections, ready := s.stepInjections(step)
	if !ready {
		return nfQueueScriptAction{}
	}

	action := nfQueueScriptAction{
		StopIngressDrops: step.stopIngressDrops,
		QueueDisposition: step.ackQueueDisposition,
		Injections:       injections,
	}

	s.applyAckQueueDisposition(step.ackQueueDisposition)
	s.advanceStep(step.advanceToDone)

	return action
}

func (s *nfQueueScriptState) stepInjections(step NFQueueScriptStep) ([]nfQueueInjection, bool) {
	switch step.trigger {
	case nfQueueScriptTriggerInitialHolesReady:
		if !s.ackState.Valid {
			return nil, false
		}

		ack, sackBlocks, resolvedDroppedSeqs, resolvedSegments, ok := s.resolveInitialObservedHoles(step.holeCount)
		if !ok {
			return nil, false
		}

		s.resolvedDroppedSeqs = append([]uint32(nil), resolvedDroppedSeqs...)
		s.resolvedSegments = append([]DataSegment(nil), resolvedSegments...)
		return []nfQueueInjection{{
			Ack:        ack,
			Window:     65535,
			Count:      defaultInjectCount(step.injectCount),
			SackBlocks: append([]TcpTestEndpointSackBlock(nil), sackBlocks...),
		}}, true

	case nfQueueScriptTriggerRetransmitOfDroppedSeqObserved:
		if !s.retransmitLatched {
			return nil, false
		}

		partialAck, partialSack, ok := s.buildResolvedPartialAckPlan()
		if !ok {
			return nil, false
		}

		return []nfQueueInjection{{
			Ack:        partialAck,
			Window:     65535,
			Count:      defaultInjectCount(step.injectCount),
			SackBlocks: append([]TcpTestEndpointSackBlock(nil), partialSack...),
		}}, true
	}

	s.setLastErrorText(fmt.Sprintf("unknown scripted trigger %d", step.trigger))
	return nil, false
}

func (s *nfQueueScriptState) applyAckQueueDisposition(disposition nfQueueAckQueueDisposition) {
	switch disposition {
	case nfQueueAckQueueDispositionNone, nfQueueAckQueueDispositionKeepQueued:
		return
	case nfQueueAckQueueDispositionReplayQueued:
		s.releaseGate()
	case nfQueueAckQueueDispositionDiscardQueued:
		s.releaseGate()
	default:
		s.setLastErrorText(fmt.Sprintf("unknown ACK queue disposition %d", disposition))
	}
}

func (s *nfQueueScriptState) releaseGate() {
	if !s.gateEnabled {
		return
	}
	s.gateEnabled = false
	s.appendTrace(NFQueueScriptTraceEntry{
		Kind:   NFQueueScriptTraceGateReleased,
		Stage:  s.stage,
		Detail: "script released ACK gate",
	})
}

func (s *nfQueueScriptState) advanceStep(advanceToDone bool) {
	previous := s.stage

	if advanceToDone || s.currentStep+1 >= len(s.steps) {
		s.currentStep = len(s.steps)
		s.stage = NFQueueScriptStageDone
	} else {
		s.currentStep++
		if s.currentStep == 0 {
			s.stage = NFQueueScriptStageWaitingInitial
		} else {
			s.stage = NFQueueScriptStageWaitingPartial
		}
	}

	s.stats.Stage = s.stage
	if s.stage != previous {
		s.appendTrace(NFQueueScriptTraceEntry{
			Kind:   NFQueueScriptTraceStageAdvanced,
			Stage:  s.stage,
			Detail: fmt.Sprintf("from=%d to=%d", previous, s.stage),
		})
	}
}

func (s *nfQueueScriptState) resolveInitialObservedHoles(holeCount int) (uint32, []TcpTestEndpointSackBlock, []uint32, []DataSegment, bool) {
	segments := s.sortedSegments()
	if len(segments) == 0 {
		return 0, nil, nil, nil, false
	}

	holeCount = s.normalizeHoleCount(holeCount)
	holeIndexes, resolvedDroppedSeqs := s.holeIndexesFromResolvedDrops(segments, holeCount)
	if len(holeIndexes) < holeCount || len(holeIndexes) == 0 {
		return 0, nil, nil, nil, false
	}

	ack := segments[holeIndexes[0]].Seq
	sackBlocks := make([]TcpTestEndpointSackBlock, 0, len(holeIndexes))
	start := holeIndexes[0] + 1

	for i := 1; i < len(holeIndexes); i++ {
		if start < holeIndexes[i] {
			sackBlocks = append(sackBlocks, TcpTestEndpointSackBlock{
				Left:  segments[start].Seq,
				Right: segments[holeIndexes[i]].Seq,
			})
		}
		start = holeIndexes[i] + 1
	}

	if start < len(segments) {
		sackBlocks = append(sackBlocks, TcpTestEndpointSackBlock{
			Left:  segments[start].Seq,
			Right: segments[len(segments)-1].End,
		})
	}

	if len(sackBlocks) == 0 {
		return 0, nil, nil, nil, false
	}

	return ack, sackBlocks, resolvedDroppedSeqs, segments, true
}

func (s *nfQueueScriptState) buildResolvedPartialAckPlan() (uint32, []TcpTestEndpointSackBlock, bool) {
	if len(s.resolvedDroppedSeqs) < 2 {
		return 0, nil, false
	}

	segments := s.sortedSegments()
	holeIndexes, _ := s.holeIndexesForDroppedSeqs(segments, s.resolvedDroppedSeqs, 2)
	if len(holeIndexes) < 2 {
		return 0, nil, false
	}

	secondHole := holeIndexes[1]
	if secondHole+1 >= len(segments) {
		return 0, nil, false
	}

	return segments[secondHole].Seq, []TcpTestEndpointSackBlock{{
		Left:  segments[secondHole+1].Seq,
		Right: segments[len(segments)-1].End,
	}}, true
}

func (s *nfQueueScriptState) normalizeHoleCount(holeCount int) int {
	if holeCount > 0 {
		return holeCount
	}
	if len(s.cfg.dropDataPacketIndices) > 0 {
		return len(s.cfg.dropDataPacketIndices)
	}
	return 1
}

func (s *nfQueueScriptState) holeIndexesFromResolvedDrops(segments []DataSegment,
	holeCount int) ([]int, []uint32) {
	droppedSeqs := make([]uint32, 0, len(s.droppedOriginalSeq))
	for seq := range s.droppedOriginalSeq {
		droppedSeqs = append(droppedSeqs, seq)
	}
	sort.Slice(droppedSeqs, func(i, j int) bool {
		return droppedSeqs[i] < droppedSeqs[j]
	})

	return s.holeIndexesForDroppedSeqs(segments, droppedSeqs, holeCount)
}

func (s *nfQueueScriptState) holeIndexesForDroppedSeqs(segments []DataSegment,
	droppedSeqs []uint32, holeCount int) ([]int, []uint32) {
	if holeCount <= 0 {
		return nil, nil
	}

	selected := make(map[uint32]struct{}, holeCount)
	for _, seq := range droppedSeqs {
		selected[seq] = struct{}{}
		if len(selected) >= holeCount {
			break
		}
	}

	holeIndexes := make([]int, 0, holeCount)
	resolved := make([]uint32, 0, holeCount)
	for i, segment := range segments {
		if _, ok := selected[segment.Seq]; !ok {
			continue
		}
		holeIndexes = append(holeIndexes, i)
		resolved = append(resolved, segment.Seq)
		if len(holeIndexes) >= holeCount {
			break
		}
	}

	return holeIndexes, resolved
}

func (s *nfQueueScriptState) sortedSegments() []DataSegment {
	segments := make([]DataSegment, 0, len(s.dataSegments))
	for seq, end := range s.dataSegments {
		segments = append(segments, DataSegment{Seq: seq, End: end})
	}
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].Seq < segments[j].Seq
	})
	return segments
}

func (s *nfQueueScriptState) setLastErrorText(text string) {
	if text == "" || s.stats.LastErrorText != "" {
		return
	}
	s.stats.LastErrorText = text
}

func (s *nfQueueScriptState) appendTrace(entry NFQueueScriptTraceEntry) {
	if len(s.trace) >= nfQueueScriptTraceCapacity {
		copy(s.trace, s.trace[1:])
		s.trace = s.trace[:nfQueueScriptTraceCapacity-1]
	}
	s.trace = append(s.trace, entry)
}

func cloneNFQueueScriptConfig(cfg NFQueueScriptConfig) NFQueueScriptConfig {
	cfg.dropDataPacketIndices = append([]uint32(nil), cfg.dropDataPacketIndices...)
	cfg.steps = cloneNFQueueScriptSteps(cfg.steps)
	return cfg
}

func cloneNFQueueScriptSteps(steps []NFQueueScriptStep) []NFQueueScriptStep {
	return append([]NFQueueScriptStep(nil), steps...)
}

func defaultInjectCount(count int) int {
	if count > 0 {
		return count
	}
	return 1
}
