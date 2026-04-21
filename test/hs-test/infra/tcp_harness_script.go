package hst

import (
	"fmt"
	"sort"
)

const tcpHarnessNFQueueScriptTraceCapacity = 128
const tcpHarnessNFQueueScriptTraceLimit = tcpHarnessNFQueueScriptTraceCapacity

type TcpHarnessDataSegment struct {
	Seq uint32
	End uint32
}

type TcpHarnessNFQueueAckState struct {
	SeqEnd  uint32
	Ack     uint32
	Valid   bool
	SrcPort uint16
	DstPort uint16
}

type TcpHarnessNFQueueScriptStage uint8

const (
	TcpHarnessNFQueueScriptStageWaitingInitial TcpHarnessNFQueueScriptStage = iota
	TcpHarnessNFQueueScriptStageWaitingPartial
	TcpHarnessNFQueueScriptStageDone
)

type TcpHarnessNFQueueScriptTrigger uint8

const (
	TcpHarnessNFQueueScriptTriggerInitialHolesReady TcpHarnessNFQueueScriptTrigger = iota
	TcpHarnessNFQueueScriptTriggerRetransmitOfDroppedSeqObserved
)

type TcpHarnessNFQueueInjectionKind uint8

const (
	TcpHarnessNFQueueInjectionKindObservedHolesSack TcpHarnessNFQueueInjectionKind = iota
	TcpHarnessNFQueueInjectionKindObservedPartialAck
)

type TcpHarnessNFQueueAckQueueDisposition uint8

const (
	tcpHarnessNFQueueAckQueueDispositionNone TcpHarnessNFQueueAckQueueDisposition = iota
	TcpHarnessNFQueueAckQueueDispositionKeepQueued
	TcpHarnessNFQueueAckQueueDispositionReplayQueued
	TcpHarnessNFQueueAckQueueDispositionDiscardQueued
)

type TcpHarnessNFQueueScriptStep struct {
	Trigger             TcpHarnessNFQueueScriptTrigger
	InjectionKind       TcpHarnessNFQueueInjectionKind
	HoleCount           int
	InjectCount         int
	StopIngressDrops    bool
	AckQueueDisposition TcpHarnessNFQueueAckQueueDisposition
	AdvanceToDone       bool
}

type TcpHarnessNFQueueScriptConfig struct {
	DropDataPacketIndices []uint32
	Steps                 []TcpHarnessNFQueueScriptStep
}

type TcpHarnessNFQueueScriptTraceEventKind uint8

const (
	TcpHarnessNFQueueScriptTraceDataSegmentObserved TcpHarnessNFQueueScriptTraceEventKind = iota
	TcpHarnessNFQueueScriptTraceOriginalDataDrop
	TcpHarnessNFQueueScriptTraceRetransmitObserved
	TcpHarnessNFQueueScriptTraceNaturalAckQueued
	TcpHarnessNFQueueScriptTraceNaturalAckDropped
	TcpHarnessNFQueueScriptTraceSyntheticAckInjected
	TcpHarnessNFQueueScriptTraceQueuedAckReplayed
	TcpHarnessNFQueueScriptTraceQueuedAckDiscarded
	TcpHarnessNFQueueScriptTraceStageAdvanced
	TcpHarnessNFQueueScriptTraceGateReleased
)

type TcpHarnessNFQueueScriptTraceEntry struct {
	Kind   TcpHarnessNFQueueScriptTraceEventKind
	Stage  TcpHarnessNFQueueScriptStage
	Seq    uint32
	Ack    uint32
	Detail string
}

type TcpHarnessNFQueueScriptStats struct {
	Stage                     TcpHarnessNFQueueScriptStage
	OriginalDropCount         uint64
	RetransmitTriggerCount    uint64
	NaturalAckQueuedCount     uint64
	NaturalAckDroppedCount    uint64
	SyntheticAckInjectedCount uint64
	QueuedAckReplayedCount    uint64
	QueuedAckDiscardedCount   uint64
	LastErrorText             string
	ResolvedDroppedSeqs       []uint32
	ResolvedSegments          []TcpHarnessDataSegment
}

type tcpHarnessNFQueueInjection struct {
	Ack        uint32
	Window     uint16
	Count      int
	SackBlocks []TcpTestEndpointSackBlock
}

type tcpHarnessNFQueueScriptEvent struct {
	Role           tcpHarnessNFQueueRole
	Packet         PcapIPv4TCPPacket
	OriginalDrop   bool
	RetransmitSeen bool
}

type tcpHarnessNFQueueScriptAction struct {
	DropNaturalAck   bool
	QueueNaturalAck  bool
	StopIngressDrops bool
	QueueDisposition TcpHarnessNFQueueAckQueueDisposition
	Injections       []tcpHarnessNFQueueInjection
}

type tcpHarnessNFQueueScriptState struct {
	cfg                 TcpHarnessNFQueueScriptConfig
	steps               []TcpHarnessNFQueueScriptStep
	stage               TcpHarnessNFQueueScriptStage
	currentStep         int
	gateEnabled         bool
	retransmitLatched   bool
	pendingQueuedAcks   int
	dataSegments        map[uint32]uint32
	droppedOriginalSeq  map[uint32]struct{}
	resolvedDroppedSeqs []uint32
	resolvedSegments    []TcpHarnessDataSegment
	ackState            TcpHarnessNFQueueAckState
	stats               TcpHarnessNFQueueScriptStats
	trace               []TcpHarnessNFQueueScriptTraceEntry
}

func BuildTwoHolesPartialAckScript(dropDataPacketIndices []uint32) TcpHarnessNFQueueScriptConfig {
	return TcpHarnessNFQueueScriptConfig{
		DropDataPacketIndices: append([]uint32(nil), dropDataPacketIndices...),
		Steps: []TcpHarnessNFQueueScriptStep{
			{
				Trigger:             TcpHarnessNFQueueScriptTriggerInitialHolesReady,
				InjectionKind:       TcpHarnessNFQueueInjectionKindObservedHolesSack,
				HoleCount:           2,
				InjectCount:         3,
				StopIngressDrops:    true,
				AckQueueDisposition: TcpHarnessNFQueueAckQueueDispositionKeepQueued,
			},
			{
				Trigger:             TcpHarnessNFQueueScriptTriggerRetransmitOfDroppedSeqObserved,
				InjectionKind:       TcpHarnessNFQueueInjectionKindObservedPartialAck,
				InjectCount:         2,
				AckQueueDisposition: TcpHarnessNFQueueAckQueueDispositionDiscardQueued,
				AdvanceToDone:       true,
			},
		},
	}
}

func BuildScoreboardStressScript(dropDataPacketIndices []uint32) TcpHarnessNFQueueScriptConfig {
	return TcpHarnessNFQueueScriptConfig{
		DropDataPacketIndices: append([]uint32(nil), dropDataPacketIndices...),
		Steps: []TcpHarnessNFQueueScriptStep{{
			Trigger:             TcpHarnessNFQueueScriptTriggerInitialHolesReady,
			InjectionKind:       TcpHarnessNFQueueInjectionKindObservedHolesSack,
			HoleCount:           len(dropDataPacketIndices),
			InjectCount:         3,
			StopIngressDrops:    true,
			AckQueueDisposition: TcpHarnessNFQueueAckQueueDispositionDiscardQueued,
			AdvanceToDone:       true,
		}},
	}
}

func BuildLostRetransmitThenRtoScript(dropDataPacketIndices []uint32) TcpHarnessNFQueueScriptConfig {
	return BuildScoreboardStressScript(dropDataPacketIndices)
}

func newTcpHarnessNFQueueScriptState(cfg TcpHarnessNFQueueScriptConfig) *tcpHarnessNFQueueScriptState {
	state := &tcpHarnessNFQueueScriptState{
		cfg:                cloneTcpHarnessNFQueueScriptConfig(cfg),
		stage:              TcpHarnessNFQueueScriptStageWaitingInitial,
		gateEnabled:        true,
		dataSegments:       make(map[uint32]uint32),
		droppedOriginalSeq: make(map[uint32]struct{}),
	}
	state.steps = cloneTcpHarnessNFQueueScriptSteps(state.cfg.Steps)
	state.stats.Stage = state.stage
	return state
}

func (s *tcpHarnessNFQueueScriptState) CurrentStage() TcpHarnessNFQueueScriptStage {
	return s.stage
}

func (s *tcpHarnessNFQueueScriptState) DroppedOriginalSeqSeen(seq uint32) bool {
	_, ok := s.droppedOriginalSeq[seq]
	return ok
}

func (s *tcpHarnessNFQueueScriptState) Stats() TcpHarnessNFQueueScriptStats {
	stats := s.stats
	stats.Stage = s.stage
	stats.ResolvedDroppedSeqs = append([]uint32(nil), s.resolvedDroppedSeqs...)
	stats.ResolvedSegments = append([]TcpHarnessDataSegment(nil), s.resolvedSegments...)
	return stats
}

func (s *tcpHarnessNFQueueScriptState) Trace() []TcpHarnessNFQueueScriptTraceEntry {
	return append([]TcpHarnessNFQueueScriptTraceEntry(nil), s.trace...)
}

func (s *tcpHarnessNFQueueScriptState) SetLastErrorText(text string) {
	s.setLastErrorText(text)
}

func (s *tcpHarnessNFQueueScriptState) RecordNaturalAckQueued(packet PcapIPv4TCPPacket) {
	s.stats.NaturalAckQueuedCount++
	s.pendingQueuedAcks++
	s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
		Kind:   TcpHarnessNFQueueScriptTraceNaturalAckQueued,
		Stage:  s.stage,
		Seq:    packet.Seq,
		Ack:    packet.Ack,
		Detail: "natural ACK queued by NFQUEUE adapter",
	})
}

func (s *tcpHarnessNFQueueScriptState) RecordSyntheticAckInjected(spec tcpHarnessNFQueueInjection) {
	if spec.Count > 0 {
		s.stats.SyntheticAckInjectedCount += uint64(spec.Count)
	}
	s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
		Kind:   TcpHarnessNFQueueScriptTraceSyntheticAckInjected,
		Stage:  s.stage,
		Ack:    spec.Ack,
		Detail: fmt.Sprintf("count=%d sack_blocks=%d", spec.Count, len(spec.SackBlocks)),
	})
}

func (s *tcpHarnessNFQueueScriptState) RecordQueuedAckReplayed(packet PcapIPv4TCPPacket) {
	if s.pendingQueuedAcks > 0 {
		s.pendingQueuedAcks--
	}
	s.stats.QueuedAckReplayedCount++
	s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
		Kind:   TcpHarnessNFQueueScriptTraceQueuedAckReplayed,
		Stage:  s.stage,
		Seq:    packet.Seq,
		Ack:    packet.Ack,
		Detail: "queued natural ACK replayed",
	})
}

func (s *tcpHarnessNFQueueScriptState) RecordQueuedAckDiscarded(packet PcapIPv4TCPPacket) {
	if s.pendingQueuedAcks > 0 {
		s.pendingQueuedAcks--
	}
	s.stats.QueuedAckDiscardedCount++
	s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
		Kind:   TcpHarnessNFQueueScriptTraceQueuedAckDiscarded,
		Stage:  s.stage,
		Seq:    packet.Seq,
		Ack:    packet.Ack,
		Detail: "queued natural ACK discarded",
	})
}

func (s *tcpHarnessNFQueueScriptState) ApplyEvent(event tcpHarnessNFQueueScriptEvent) tcpHarnessNFQueueScriptAction {
	s.observeEvent(event)

	action := tcpHarnessNFQueueScriptAction{}
	if s.shouldGateNaturalAck(event) {
		action.DropNaturalAck = true
		action.QueueNaturalAck = true
		s.stats.NaturalAckDroppedCount++
		s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
			Kind:   TcpHarnessNFQueueScriptTraceNaturalAckDropped,
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
	action.DropNaturalAck = action.DropNaturalAck || stepAction.DropNaturalAck
	action.QueueNaturalAck = action.QueueNaturalAck || stepAction.QueueNaturalAck

	return action
}

func (s *tcpHarnessNFQueueScriptState) observeEvent(event tcpHarnessNFQueueScriptEvent) {
	if event.Packet.PayloadLen > 0 {
		end := event.Packet.SeqEnd()
		if prevEnd, ok := s.dataSegments[event.Packet.Seq]; !ok || end > prevEnd {
			s.dataSegments[event.Packet.Seq] = end
			s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
				Kind:   TcpHarnessNFQueueScriptTraceDataSegmentObserved,
				Stage:  s.stage,
				Seq:    event.Packet.Seq,
				Ack:    event.Packet.Ack,
				Detail: fmt.Sprintf("segment end=%d payload=%d", end, event.Packet.PayloadLen),
			})
		}
	}

	if event.Role == tcpHarnessNFQueueRoleEgress && event.Packet.Flags&tcpFlagAck != 0 {
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
			s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
				Kind:   TcpHarnessNFQueueScriptTraceOriginalDataDrop,
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
		s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
			Kind:   TcpHarnessNFQueueScriptTraceRetransmitObserved,
			Stage:  s.stage,
			Seq:    event.Packet.Seq,
			Ack:    event.Packet.Ack,
			Detail: "retransmit of previously dropped sequence observed",
		})
	}
}

func (s *tcpHarnessNFQueueScriptState) shouldGateNaturalAck(event tcpHarnessNFQueueScriptEvent) bool {
	return event.Role == tcpHarnessNFQueueRoleEgress &&
		s.gateEnabled &&
		event.Packet.IsAckOnly() &&
		!event.Packet.IsSyntheticHarnessAck()
}

func (s *tcpHarnessNFQueueScriptState) applyCurrentStep() tcpHarnessNFQueueScriptAction {
	if s.stage == TcpHarnessNFQueueScriptStageDone || s.currentStep >= len(s.steps) {
		return tcpHarnessNFQueueScriptAction{}
	}

	step := s.steps[s.currentStep]
	injections, ready := s.stepInjections(step)
	if !ready {
		return tcpHarnessNFQueueScriptAction{}
	}

	action := tcpHarnessNFQueueScriptAction{
		StopIngressDrops: step.StopIngressDrops,
		QueueDisposition: step.AckQueueDisposition,
		Injections:       injections,
	}

	s.applyAckQueueDisposition(step.AckQueueDisposition)
	s.advanceStep(step.AdvanceToDone)

	return action
}

func (s *tcpHarnessNFQueueScriptState) stepInjections(step TcpHarnessNFQueueScriptStep) ([]tcpHarnessNFQueueInjection, bool) {
	switch step.Trigger {
	case TcpHarnessNFQueueScriptTriggerInitialHolesReady:
		if !s.ackState.Valid {
			return nil, false
		}

		ack, sackBlocks, resolvedDroppedSeqs, resolvedSegments, ok := s.resolveInitialObservedHoles(step.HoleCount)
		if !ok {
			return nil, false
		}

		s.resolvedDroppedSeqs = append([]uint32(nil), resolvedDroppedSeqs...)
		s.resolvedSegments = append([]TcpHarnessDataSegment(nil), resolvedSegments...)
		return []tcpHarnessNFQueueInjection{{
			Ack:        ack,
			Window:     65535,
			Count:      defaultInjectCount(step.InjectCount),
			SackBlocks: append([]TcpTestEndpointSackBlock(nil), sackBlocks...),
		}}, true

	case TcpHarnessNFQueueScriptTriggerRetransmitOfDroppedSeqObserved:
		if !s.retransmitLatched {
			return nil, false
		}

		partialAck, partialSack, ok := s.buildResolvedPartialAckPlan()
		if !ok {
			return nil, false
		}

		return []tcpHarnessNFQueueInjection{{
			Ack:        partialAck,
			Window:     65535,
			Count:      defaultInjectCount(step.InjectCount),
			SackBlocks: append([]TcpTestEndpointSackBlock(nil), partialSack...),
		}}, true
	}

	s.setLastErrorText(fmt.Sprintf("unknown scripted trigger %d", step.Trigger))
	return nil, false
}

func (s *tcpHarnessNFQueueScriptState) applyAckQueueDisposition(disposition TcpHarnessNFQueueAckQueueDisposition) {
	switch disposition {
	case tcpHarnessNFQueueAckQueueDispositionNone, TcpHarnessNFQueueAckQueueDispositionKeepQueued:
		return
	case TcpHarnessNFQueueAckQueueDispositionReplayQueued:
		s.releaseGate()
	case TcpHarnessNFQueueAckQueueDispositionDiscardQueued:
		s.releaseGate()
	default:
		s.setLastErrorText(fmt.Sprintf("unknown ACK queue disposition %d", disposition))
	}
}

func (s *tcpHarnessNFQueueScriptState) releaseGate() {
	if !s.gateEnabled {
		return
	}
	s.gateEnabled = false
	s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
		Kind:   TcpHarnessNFQueueScriptTraceGateReleased,
		Stage:  s.stage,
		Detail: "script released ACK gate",
	})
}

func (s *tcpHarnessNFQueueScriptState) advanceStep(advanceToDone bool) {
	previous := s.stage

	if advanceToDone || s.currentStep+1 >= len(s.steps) {
		s.currentStep = len(s.steps)
		s.stage = TcpHarnessNFQueueScriptStageDone
	} else {
		s.currentStep++
		if s.currentStep == 0 {
			s.stage = TcpHarnessNFQueueScriptStageWaitingInitial
		} else {
			s.stage = TcpHarnessNFQueueScriptStageWaitingPartial
		}
	}

	s.stats.Stage = s.stage
	if s.stage != previous {
		s.appendTrace(TcpHarnessNFQueueScriptTraceEntry{
			Kind:   TcpHarnessNFQueueScriptTraceStageAdvanced,
			Stage:  s.stage,
			Detail: fmt.Sprintf("from=%d to=%d", previous, s.stage),
		})
	}
}

func (s *tcpHarnessNFQueueScriptState) resolveInitialObservedHoles(holeCount int) (uint32, []TcpTestEndpointSackBlock, []uint32, []TcpHarnessDataSegment, bool) {
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

func (s *tcpHarnessNFQueueScriptState) buildResolvedPartialAckPlan() (uint32, []TcpTestEndpointSackBlock, bool) {
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

func (s *tcpHarnessNFQueueScriptState) normalizeHoleCount(holeCount int) int {
	if holeCount > 0 {
		return holeCount
	}
	if len(s.cfg.DropDataPacketIndices) > 0 {
		return len(s.cfg.DropDataPacketIndices)
	}
	return 1
}

func (s *tcpHarnessNFQueueScriptState) holeIndexesFromResolvedDrops(segments []TcpHarnessDataSegment,
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

func (s *tcpHarnessNFQueueScriptState) holeIndexesForDroppedSeqs(segments []TcpHarnessDataSegment,
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

func (s *tcpHarnessNFQueueScriptState) sortedSegments() []TcpHarnessDataSegment {
	segments := make([]TcpHarnessDataSegment, 0, len(s.dataSegments))
	for seq, end := range s.dataSegments {
		segments = append(segments, TcpHarnessDataSegment{Seq: seq, End: end})
	}
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].Seq < segments[j].Seq
	})
	return segments
}

func (s *tcpHarnessNFQueueScriptState) setLastErrorText(text string) {
	if text == "" || s.stats.LastErrorText != "" {
		return
	}
	s.stats.LastErrorText = text
}

func (s *tcpHarnessNFQueueScriptState) appendTrace(entry TcpHarnessNFQueueScriptTraceEntry) {
	if len(s.trace) >= tcpHarnessNFQueueScriptTraceCapacity {
		copy(s.trace, s.trace[1:])
		s.trace = s.trace[:tcpHarnessNFQueueScriptTraceCapacity-1]
	}
	s.trace = append(s.trace, entry)
}

func cloneTcpHarnessNFQueueScriptConfig(cfg TcpHarnessNFQueueScriptConfig) TcpHarnessNFQueueScriptConfig {
	cfg.DropDataPacketIndices = append([]uint32(nil), cfg.DropDataPacketIndices...)
	cfg.Steps = cloneTcpHarnessNFQueueScriptSteps(cfg.Steps)
	return cfg
}

func cloneTcpHarnessNFQueueScriptSteps(steps []TcpHarnessNFQueueScriptStep) []TcpHarnessNFQueueScriptStep {
	return append([]TcpHarnessNFQueueScriptStep(nil), steps...)
}

func defaultInjectCount(count int) int {
	if count > 0 {
		return count
	}
	return 1
}
