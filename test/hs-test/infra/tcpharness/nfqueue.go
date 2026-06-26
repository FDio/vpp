/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package tcpharness

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const nfQueueAckQueueCapacity = 128

type Logf func(log any, args ...any)

type TCPPacketConfig struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Window     uint16
	Flags      uint8
	Payload    []byte
	SackBlocks []TcpTestEndpointSackBlock
}

func BuildIPv4TCPPacket(cfg TCPPacketConfig) ([]byte, error) {
	src := cfg.SrcIP.To4()
	dst := cfg.DstIP.To4()
	if src == nil || dst == nil {
		return nil, fmt.Errorf("expected IPv4 addresses")
	}
	if len(cfg.SackBlocks) > tcpMaxSackBlocks {
		return nil, fmt.Errorf("too many SACK blocks: %d", len(cfg.SackBlocks))
	}

	options := make([]layers.TCPOption, 0, 2)
	if len(cfg.SackBlocks) > 0 {
		sackData := make([]byte, len(cfg.SackBlocks)*tcpOptionSackBlockLen)
		for i, sack := range cfg.SackBlocks {
			offset := i * tcpOptionSackBlockLen
			binary.BigEndian.PutUint32(sackData[offset:offset+4], sack.Left)
			binary.BigEndian.PutUint32(sackData[offset+4:offset+8], sack.Right)
		}
		options = append(options,
			layers.TCPOption{OptionType: layers.TCPOptionKindNop},
			layers.TCPOption{OptionType: layers.TCPOptionKindSACK, OptionData: sackData},
		)
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      syntheticAckTTL,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    append(net.IP(nil), src...),
		DstIP:    append(net.IP(nil), dst...),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(cfg.SrcPort),
		DstPort: layers.TCPPort(cfg.DstPort),
		Seq:     cfg.Seq,
		Ack:     cfg.Ack,
		FIN:     cfg.Flags&tcpFlagFin != 0,
		SYN:     cfg.Flags&tcpFlagSyn != 0,
		RST:     cfg.Flags&tcpFlagRst != 0,
		PSH:     cfg.Flags&tcpFlagPsh != 0,
		ACK:     cfg.Flags&tcpFlagAck != 0,
		URG:     cfg.Flags&tcpFlagUrg != 0,
		ECE:     cfg.Flags&tcpFlagEce != 0,
		CWR:     cfg.Flags&tcpFlagCwr != 0,
		Window:  cfg.Window,
		Options: options,
	}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ipv4, tcp, gopacket.Payload(cfg.Payload)); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func buildIPv4AckPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	seq, ack uint32, window uint16,
	sackBlocks []TcpTestEndpointSackBlock) ([]byte, error) {
	return BuildIPv4TCPPacket(TCPPacketConfig{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        seq,
		Ack:        ack,
		Window:     window,
		Flags:      tcpFlagAck,
		SackBlocks: sackBlocks,
	})
}

func SendIPv4RawPacket(packet []byte, dstIP net.IP) error {
	dst := dstIP.To4()
	if dst == nil {
		return fmt.Errorf("expected IPv4 destination")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}

	var sockaddr unix.SockaddrInet4
	copy(sockaddr.Addr[:], dst)
	return unix.Sendto(fd, packet, 0, &sockaddr)
}

func sendIPv4RawPacket(packet []byte, dstIP net.IP) error {
	return SendIPv4RawPacket(packet, dstIP)
}

type NFQueueConfig struct {
	QueueNum              uint16
	InputIf               string
	OutputIf              string
	SrcIP                 string
	DstIP                 string
	SrcPort               uint16
	DstPort               uint16
	DropDataPacketIndices []uint32
	// DropRetransmitCount, if > 0, drops that many successive retransmits of
	// each originally-dropped segment in addition to the original. 1 drops just
	// the first retransmit; higher values exercise repeated loss of the same
	// segment (e.g. RTO backoff behavior).
	DropRetransmitCount uint32
	DropAckOnlyPackets  bool
	SynOptionRewrite    SynOptionRewriteConfig
}

type SynOptionRewriteConfig struct {
	StripSackPermitted    bool
	StripTimestamps       bool
	StopAfterFirstRewrite bool
}

func (cfg SynOptionRewriteConfig) enabled() bool {
	return cfg.StripSackPermitted || cfg.StripTimestamps
}

type NFQueueStats struct {
	DataSeen        uint32
	DropCount       uint32
	DroppedSeqs     []uint32
	RetransmitCount uint32
	RetransmitSeqs  []uint32
	SynRewriteCount uint32
}

type NFQueueController struct {
	ingress *NFQueueHelper
	ackGate *NFQueueHelper

	mu      sync.Mutex
	script  *nfQueueScriptState
	lastErr error
	logf    Logf
}

type queuedAck struct {
	raw    []byte
	packet PcapIPv4TCPPacket
}

type NFQueueHelper struct {
	cfg                   NFQueueConfig
	tableName             string
	nf                    *nfqueue.Nfqueue
	cancel                context.CancelFunc
	dropDataPacketIndices map[uint32]struct{}
	retransmitTargets     map[uint32]uint32
	seenDataSeqs          map[uint32]struct{}
	originalDroppedSeqs   map[uint32]struct{}
	role                  nfQueueRole
	controller            *NFQueueController
	dropsStopped          bool

	mu              sync.Mutex
	dataSeen        uint32
	dropCount       uint32
	droppedSeqs     []uint32
	retransmitCount uint32
	retransmitSeqs  []uint32
	synRewriteCount uint32
	ackState        NFQueueAckState
	queuedAcks      []queuedAck
	lastErr         error
	logf            Logf
}

func (cfg NFQueueConfig) table() string {
	return fmt.Sprintf("tcp_harness_%d", cfg.QueueNum)
}

func (cfg NFQueueConfig) nftScript() string {
	match := []string{
		fmt.Sprintf("ip saddr %s", cfg.SrcIP),
		fmt.Sprintf("ip daddr %s", cfg.DstIP),
	}
	hook := "input"
	if cfg.OutputIf != "" {
		hook = "output"
		match = append([]string{fmt.Sprintf(`oifname "%s"`, cfg.OutputIf)}, match...)
	} else if cfg.InputIf != "" {
		match = append([]string{fmt.Sprintf(`iifname "%s"`, cfg.InputIf)}, match...)
	}
	if cfg.SrcPort != 0 {
		match = append(match, fmt.Sprintf("tcp sport %d", cfg.SrcPort))
	}
	if cfg.DstPort != 0 {
		match = append(match, fmt.Sprintf("tcp dport %d", cfg.DstPort))
	}
	match = append(match, fmt.Sprintf("queue num %d bypass", cfg.QueueNum))

	return fmt.Sprintf(`table inet %s {
	chain %s {
		type filter hook %s priority 0; policy accept;
		%s
	}
}
`, cfg.table(), hook, hook, strings.Join(match, " "))
}

func runNftScript(script string) (string, error) {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func deleteNftTable(table string, logf Logf) {
	cmd := exec.Command("nft", "delete", "table", "inet", table)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) > 0 &&
		!strings.Contains(string(out), "No such file or directory") {
		if logf != nil {
			logf(strings.TrimSpace(string(out)))
		}
	}
}

func modprobeNFNetlinkQueue(logf Logf) {
	cmd := exec.Command("modprobe", "nfnetlink_queue")
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) > 0 &&
		!strings.Contains(string(out), "Module nfnetlink_queue not found") {
		if logf != nil {
			logf(strings.TrimSpace(string(out)))
		}
	}
}

func newNFQueueHelperWithRole(cfg NFQueueConfig,
	role nfQueueRole, controller *NFQueueController, logf Logf) (*NFQueueHelper, error) {
	h := &NFQueueHelper{
		cfg:                   cfg,
		tableName:             cfg.table(),
		dropDataPacketIndices: make(map[uint32]struct{}, len(cfg.DropDataPacketIndices)),
		retransmitTargets:     make(map[uint32]uint32),
		seenDataSeqs:          make(map[uint32]struct{}),
		originalDroppedSeqs:   make(map[uint32]struct{}),
		role:                  role,
		controller:            controller,
		logf:                  logf,
	}
	for _, packetIndex := range cfg.DropDataPacketIndices {
		h.dropDataPacketIndices[packetIndex] = struct{}{}
	}

	modprobeNFNetlinkQueue(logf)
	deleteNftTable(h.tableName, logf)

	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      cfg.QueueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_INET,
		WriteTimeout: 15 * time.Millisecond,
	})
	if err != nil {
		return nil, err
	}
	h.nf = nf
	if err := h.nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		h.nf.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	if err := h.nf.RegisterWithErrorFunc(ctx, h.handlePacket, h.handleError); err != nil {
		cancel()
		h.nf.Close()
		return nil, err
	}

	if out, err := runNftScript(cfg.nftScript()); err != nil {
		cancel()
		h.nf.Close()
		return nil, fmt.Errorf("failed to install nft NFQUEUE rule: %w: %s", err, out)
	}

	return h, nil
}

func NewNFQueueHelper(cfg NFQueueConfig, logf Logf) (*NFQueueHelper, error) {
	return newNFQueueHelperWithRole(cfg, nfQueueRoleIngress, nil, logf)
}

func NewNFQueueController(cfg NFQueueScriptConfig,
	ingressCfg NFQueueConfig, ackGateCfg NFQueueConfig,
	logf Logf) (*NFQueueController, error) {
	controller := &NFQueueController{
		script: newNFQueueScriptState(cfg),
		logf:   logf,
	}

	ingress, err := newNFQueueHelperWithRole(ingressCfg, nfQueueRoleIngress, controller, logf)
	if err != nil {
		return nil, err
	}
	controller.ingress = ingress

	ackGate, err := newNFQueueHelperWithRole(ackGateCfg, nfQueueRoleEgress, controller, logf)
	if err != nil {
		ingress.Close()
		return nil, err
	}
	controller.ackGate = ackGate

	return controller, nil
}

func (c *NFQueueController) Ingress() *NFQueueHelper {
	return c.ingress
}

func (c *NFQueueController) AckGate() *NFQueueHelper {
	return c.ackGate
}

func (c *NFQueueController) setError(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	if c.lastErr == nil {
		c.lastErr = err
		c.script.SetLastErrorText(err.Error())
	}
	c.mu.Unlock()
}

func (c *NFQueueController) CurrentStats() (NFQueueScriptStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.script.Stats(), c.lastErr
}

func (c *NFQueueController) CurrentTrace() ([]NFQueueScriptTraceEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.script.Trace(), c.lastErr
}

func (c *NFQueueController) Close() {
	if c.ingress != nil {
		c.ingress.Close()
	}
	if c.ackGate != nil {
		c.ackGate.Close()
	}
}

func (c *NFQueueController) injectAck(spec nfQueueInjection) error {
	if c.ackGate == nil {
		return fmt.Errorf("no ACK-gate helper available")
	}

	for i := 0; i < spec.Count; i++ {
		if err := c.ackGate.injectAck(spec.Ack, spec.Window, spec.SackBlocks...); err != nil {
			return err
		}
	}

	return nil
}

func (c *NFQueueController) recordNaturalAckQueued(packet PcapIPv4TCPPacket) {
	c.mu.Lock()
	c.script.RecordNaturalAckQueued(packet)
	c.mu.Unlock()
}

func (c *NFQueueController) recordSyntheticAckInjected(spec nfQueueInjection) {
	c.mu.Lock()
	c.script.RecordSyntheticAckInjected(spec)
	c.mu.Unlock()
}

func (c *NFQueueController) recordQueuedAckReplayed(packet PcapIPv4TCPPacket) {
	c.mu.Lock()
	c.script.RecordQueuedAckReplayed(packet)
	c.mu.Unlock()
}

func (c *NFQueueController) recordQueuedAckDiscarded(packet PcapIPv4TCPPacket) {
	c.mu.Lock()
	c.script.RecordQueuedAckDiscarded(packet)
	c.mu.Unlock()
}

func (c *NFQueueController) stopIngressDrops() {
	if c.ingress != nil {
		c.ingress.StopDrops()
	}
}

func (c *NFQueueController) applyQueueDisposition(
	disposition nfQueueAckQueueDisposition) error {
	if c.ackGate == nil || disposition == nfQueueAckQueueDispositionNone ||
		disposition == nfQueueAckQueueDispositionKeepQueued {
		return nil
	}

	switch disposition {
	case nfQueueAckQueueDispositionReplayQueued:
		return c.ackGate.replayQueuedAcks(c)
	case nfQueueAckQueueDispositionDiscardQueued:
		c.ackGate.discardQueuedAcks(c)
		return nil
	default:
		return nil
	}
}

func (c *NFQueueController) droppedOriginalSeqSeen(seq uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.script.DroppedOriginalSeqSeen(seq)
}

func (c *NFQueueController) onPacket(role nfQueueRole, packet PcapIPv4TCPPacket,
	originalDrop bool, retransmitSeen bool) nfQueueScriptAction {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.script.ApplyEvent(nfQueueScriptEvent{
		Role:           role,
		Packet:         packet,
		OriginalDrop:   originalDrop,
		RetransmitSeen: retransmitSeen,
	})
}

func cloneTCPOption(option layers.TCPOption) layers.TCPOption {
	option.OptionData = append([]byte(nil), option.OptionData...)
	return option
}

func cloneIPv4Option(option layers.IPv4Option) layers.IPv4Option {
	option.OptionData = append([]byte(nil), option.OptionData...)
	return option
}

func rewriteIPv4TCPSynOptions(raw []byte, cfg SynOptionRewriteConfig) (
	[]byte, bool, error) {
	if !cfg.enabled() {
		return raw, false, nil
	}

	packet := gopacket.NewPacket(raw, layers.LinkTypeRaw, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return raw, false, nil
	}

	ipv4, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return raw, false, nil
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return raw, false, nil
	}
	if !tcp.SYN || tcp.ACK || tcp.FIN || tcp.RST || len(tcp.Payload) != 0 {
		return raw, false, nil
	}

	options := make([]layers.TCPOption, 0, len(tcp.Options))
	changed := false
	for _, option := range tcp.Options {
		switch option.OptionType {
		case layers.TCPOptionKindSACKPermitted:
			if cfg.StripSackPermitted {
				changed = true
				continue
			}
		case layers.TCPOptionKindTimestamps:
			if cfg.StripTimestamps {
				changed = true
				continue
			}
		}
		options = append(options, cloneTCPOption(option))
	}
	if !changed {
		return raw, false, nil
	}

	ipCopy := *ipv4
	ipCopy.BaseLayer = layers.BaseLayer{}
	ipCopy.Length = 0
	ipCopy.Checksum = 0
	ipCopy.SrcIP = append(net.IP(nil), ipv4.SrcIP...)
	ipCopy.DstIP = append(net.IP(nil), ipv4.DstIP...)
	ipCopy.Options = make([]layers.IPv4Option, 0, len(ipv4.Options))
	for _, option := range ipv4.Options {
		ipCopy.Options = append(ipCopy.Options, cloneIPv4Option(option))
	}
	ipCopy.Padding = append([]byte(nil), ipv4.Padding...)

	tcpCopy := *tcp
	tcpCopy.BaseLayer = layers.BaseLayer{}
	tcpCopy.Checksum = 0
	tcpCopy.Options = options
	tcpCopy.Padding = nil
	tcpCopy.Payload = nil
	if err := tcpCopy.SetNetworkLayerForChecksum(&ipCopy); err != nil {
		return nil, false, err
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &ipCopy, &tcpCopy); err != nil {
		return nil, false, err
	}

	return buffer.Bytes(), true, nil
}

func (h *NFQueueHelper) matchPacket(packet PcapIPv4TCPPacket) bool {
	if packet.SrcIP.String() != h.cfg.SrcIP || packet.DstIP.String() != h.cfg.DstIP {
		return false
	}
	if h.cfg.SrcPort != 0 && packet.SrcPort != h.cfg.SrcPort {
		return false
	}
	if h.cfg.DstPort != 0 && packet.DstPort != h.cfg.DstPort {
		return false
	}
	return true
}

func (h *NFQueueHelper) firstSeenDataSeqLocked(packet PcapIPv4TCPPacket) bool {
	if h.seenDataSeqs == nil {
		h.seenDataSeqs = make(map[uint32]struct{})
	}
	if _, ok := h.seenDataSeqs[packet.Seq]; ok {
		return false
	}
	h.seenDataSeqs[packet.Seq] = struct{}{}
	return true
}

func (h *NFQueueHelper) recordRetransmitOfDroppedSeqLocked(packet PcapIPv4TCPPacket) {
	if _, ok := h.originalDroppedSeqs[packet.Seq]; !ok {
		return
	}
	h.retransmitCount++
	h.retransmitSeqs = append(h.retransmitSeqs, packet.Seq)
}

func (h *NFQueueHelper) dataPacketDropDecisionLocked(packet PcapIPv4TCPPacket) (
	drop bool, originalDrop bool) {
	if remaining, ok := h.retransmitTargets[packet.Seq]; ok {
		h.recordRetransmitOfDroppedSeqLocked(packet)
		if remaining <= 1 {
			delete(h.retransmitTargets, packet.Seq)
		} else {
			h.retransmitTargets[packet.Seq] = remaining - 1
		}
		return true, false
	}

	if h.dropsStopped {
		h.recordRetransmitOfDroppedSeqLocked(packet)
		return false, false
	}

	if !h.firstSeenDataSeqLocked(packet) {
		h.recordRetransmitOfDroppedSeqLocked(packet)
		return false, false
	}

	h.dataSeen++
	if _, ok := h.dropDataPacketIndices[h.dataSeen]; !ok {
		return false, false
	}

	if h.cfg.DropRetransmitCount > 0 {
		h.retransmitTargets[packet.Seq] = h.cfg.DropRetransmitCount
	}
	h.originalDroppedSeqs[packet.Seq] = struct{}{}
	return true, true
}

func (h *NFQueueHelper) StopDrops() {
	h.mu.Lock()
	h.dropsStopped = true
	clear(h.dropDataPacketIndices)
	clear(h.retransmitTargets)
	h.mu.Unlock()
}

func (h *NFQueueHelper) setError(err error) {
	if err == nil {
		return
	}
	h.mu.Lock()
	if h.lastErr == nil {
		h.lastErr = err
	}
	h.mu.Unlock()
	if h.controller != nil {
		h.controller.setError(err)
	}
}

func (h *NFQueueHelper) queueNaturalAck(raw []byte, packet PcapIPv4TCPPacket) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.queuedAcks) >= nfQueueAckQueueCapacity {
		return fmt.Errorf("queued ACK overflow: %d", len(h.queuedAcks))
	}

	h.queuedAcks = append(h.queuedAcks, queuedAck{
		raw:    append([]byte(nil), raw...),
		packet: packet,
	})
	return nil
}

func (h *NFQueueHelper) replayQueuedAcks(controller *NFQueueController) error {
	h.mu.Lock()
	queued := append([]queuedAck(nil), h.queuedAcks...)
	h.queuedAcks = nil
	h.mu.Unlock()

	for _, queuedAck := range queued {
		if err := sendIPv4RawPacket(queuedAck.raw, queuedAck.packet.DstIP); err != nil {
			return err
		}
		controller.recordQueuedAckReplayed(queuedAck.packet)
	}

	return nil
}

func (h *NFQueueHelper) discardQueuedAcks(controller *NFQueueController) {
	h.mu.Lock()
	queued := append([]queuedAck(nil), h.queuedAcks...)
	h.queuedAcks = nil
	h.mu.Unlock()

	for _, queuedAck := range queued {
		controller.recordQueuedAckDiscarded(queuedAck.packet)
	}
}

func (h *NFQueueHelper) handlePacket(a nfqueue.Attribute) int {
	if a.PacketID == nil {
		return 0
	}

	id := *a.PacketID
	verdict := nfqueue.NfAccept
	var (
		controllerActs   []nfQueueInjection
		queueDisposition nfQueueAckQueueDisposition
		queueNaturalAck  bool
		stopIngressDrops bool
		queuedAckRaw     []byte
		queuedAckPacket  PcapIPv4TCPPacket
		controller       *NFQueueController
		modifiedPacket   []byte
		synRewrite       bool
	)

	if a.Payload != nil {
		if packet, ok := parseRawIPv4TCPPacket(*a.Payload); ok && h.matchPacket(packet) {
			var (
				drop           bool
				originalDrop   bool
				retransmitSeen bool
				action         nfQueueScriptAction
			)
			controller = h.controller

			if h.cfg.SynOptionRewrite.enabled() {
				h.mu.Lock()
				rewriteSyn := !h.cfg.SynOptionRewrite.StopAfterFirstRewrite ||
					h.synRewriteCount == 0
				h.mu.Unlock()
				if rewriteSyn {
					rewritten, changed, err :=
						rewriteIPv4TCPSynOptions(*a.Payload, h.cfg.SynOptionRewrite)
					if err != nil {
						h.setError(err)
					} else if changed {
						modifiedPacket = rewritten
						synRewrite = true
					}
				}
			}

			h.mu.Lock()
			if h.cfg.OutputIf != "" && packet.Flags&tcpFlagAck != 0 {
				seqEnd := packet.SeqEnd()
				if !h.ackState.Valid || seqEnd > h.ackState.SeqEnd {
					h.ackState.SeqEnd = seqEnd
				}
				if !h.ackState.Valid || packet.Ack > h.ackState.Ack {
					h.ackState.Ack = packet.Ack
				}
				h.ackState.SrcPort = packet.SrcPort
				h.ackState.DstPort = packet.DstPort
				h.ackState.Valid = true
			}
			switch {
			case packet.PayloadLen > 0:
				drop, originalDrop = h.dataPacketDropDecisionLocked(packet)
				if h.controller != nil && !originalDrop {
					retransmitSeen = h.controller.droppedOriginalSeqSeen(packet.Seq)
				}
			case h.controller == nil && h.cfg.DropAckOnlyPackets &&
				packet.IsAckOnly() && !packet.IsSyntheticAck():
				drop = true
			}
			if h.controller != nil {
				action = h.controller.onPacket(h.role, packet, originalDrop, retransmitSeen)
				drop = drop || action.QueueNaturalAck
				controllerActs = action.Injections
				queueDisposition = action.QueueDisposition
				stopIngressDrops = action.StopIngressDrops
			}
			if drop {
				h.dropCount++
				h.droppedSeqs = append(h.droppedSeqs, packet.Seq)
				verdict = nfqueue.NfDrop
			}
			h.mu.Unlock()

			if action.QueueNaturalAck {
				queueNaturalAck = true
				queuedAckRaw = append([]byte(nil), (*a.Payload)...)
				queuedAckPacket = packet
			}
		}
	}

	if queueNaturalAck {
		if err := h.queueNaturalAck(queuedAckRaw, queuedAckPacket); err != nil {
			h.mu.Lock()
			if h.lastErr == nil {
				h.lastErr = err
			}
			h.mu.Unlock()
			if controller != nil {
				controller.setError(err)
			}
		} else if controller != nil {
			controller.recordNaturalAckQueued(queuedAckPacket)
		}
	}

	if stopIngressDrops && controller != nil {
		controller.stopIngressDrops()
	}

	var err error
	if modifiedPacket != nil {
		err = h.nf.SetVerdictModPacket(id, verdict, modifiedPacket)
	} else {
		err = h.nf.SetVerdict(id, verdict)
	}
	if err != nil {
		h.setError(err)
		return -1
	}
	if synRewrite {
		h.mu.Lock()
		h.synRewriteCount++
		h.mu.Unlock()
	}

	for _, action := range controllerActs {
		if controller != nil {
			controller.recordSyntheticAckInjected(action)
		}
		if err := controller.injectAck(action); err != nil {
			controller.setError(err)
			h.mu.Lock()
			if h.lastErr == nil {
				h.lastErr = err
			}
			h.mu.Unlock()
		}
	}

	if controller != nil {
		if err := controller.applyQueueDisposition(queueDisposition); err != nil {
			controller.setError(err)
			h.mu.Lock()
			if h.lastErr == nil {
				h.lastErr = err
			}
			h.mu.Unlock()
		}
	}

	return 0
}

func (h *NFQueueHelper) handleError(err error) int {
	if opError, ok := err.(*netlink.OpError); ok {
		if opError.Timeout() || opError.Temporary() {
			return 0
		}
	}

	h.mu.Lock()
	if h.lastErr == nil {
		h.lastErr = err
	}
	h.mu.Unlock()
	if h.controller != nil {
		h.controller.setError(err)
	}
	return -1
}

func (h *NFQueueHelper) Close() {
	deleteNftTable(h.tableName, h.logf)
	if h.cancel != nil {
		h.cancel()
	}
	if h.nf != nil {
		_ = h.nf.Close()
	}
}

func (h *NFQueueHelper) CurrentState() (uint32, []uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	seqs := append([]uint32(nil), h.droppedSeqs...)
	return h.dropCount, seqs, h.lastErr
}

func (h *NFQueueHelper) CurrentStats() (NFQueueStats, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return NFQueueStats{
		DataSeen:        h.dataSeen,
		DropCount:       h.dropCount,
		DroppedSeqs:     append([]uint32(nil), h.droppedSeqs...),
		RetransmitCount: h.retransmitCount,
		RetransmitSeqs:  append([]uint32(nil), h.retransmitSeqs...),
		SynRewriteCount: h.synRewriteCount,
	}, h.lastErr
}

func (h *NFQueueHelper) snapshotAckState() (NFQueueAckState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ackState, h.lastErr
}

func (h *NFQueueHelper) injectAck(ack uint32, window uint16,
	sackBlocks ...TcpTestEndpointSackBlock) error {
	state, err := h.snapshotAckState()
	if err != nil {
		return err
	}
	if !state.Valid {
		return fmt.Errorf("no ACK state available")
	}

	srcIP := net.ParseIP(h.cfg.SrcIP)
	dstIP := net.ParseIP(h.cfg.DstIP)
	srcPort := h.cfg.SrcPort
	dstPort := h.cfg.DstPort
	if state.SrcPort != 0 {
		srcPort = state.SrcPort
	}
	if state.DstPort != 0 {
		dstPort = state.DstPort
	}

	packet, err := buildIPv4AckPacket(srcIP, dstIP, srcPort, dstPort,
		state.SeqEnd, ack, window, sackBlocks)
	if err != nil {
		return err
	}

	return sendIPv4RawPacket(packet, dstIP)
}
