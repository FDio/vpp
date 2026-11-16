/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package main

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	tcpharness "fd.io/hs-test/infra/tcpharness"
	"go.fd.io/govpp/binapi/vlib"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const (
	tcpDelayedCleanupSyn    = 0x02
	tcpDelayedCleanupFinAck = 0x11
	tcpDelayedCleanupRstAck = 0x14
)

var tcpDelayedCleanupPoolIndexRE = regexp.MustCompile("(?m) index: ([0-9]+)")

func init() {
	RegisterTcpHarnessTests(TcpDelayedCleanupResetSurvivorTest)
}

func tcpDelayedCleanupNft(args ...string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func tcpDelayedCleanupSendTCP(src, dst net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8) {
	packet, err := tcpharness.BuildIPv4TCPControl(
		src, dst, srcPort, dstPort, seq, ack, flags)
	AssertNil(err)
	AssertNil(tcpharness.SendIPv4RawPacket(packet, dst))
}

func tcpDelayedCleanupTryCaptureServerControl(fd int, src, dst net.IP, srcPort, dstPort uint16,
	ack uint32, wantSyn, wantFin bool, timeout time.Duration) (uint32, bool) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	AssertNil(unix.SetNonblock(fd, true))

	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			time.Sleep(time.Millisecond)
			continue
		}
		AssertNil(err)
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipLayer == nil || tcpLayer == nil {
			continue
		}
		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)
		if !ip.SrcIP.Equal(src) || !ip.DstIP.Equal(dst) ||
			uint16(tcp.SrcPort) != srcPort || uint16(tcp.DstPort) != dstPort ||
			tcp.Ack != ack || tcp.SYN != wantSyn || tcp.FIN != wantFin ||
			!tcp.ACK || tcp.RST {
			continue
		}
		return tcp.Seq, true
	}
	return 0, false
}

func tcpDelayedCleanupPoolIndex(vpp *VppInstance, clientIP net.IP, clientPort uint16) (string, string) {
	cmd := fmt.Sprintf("show session verbose 2 proto tcp rmt %s:%d",
		clientIP.String(), clientPort)
	AssertNil(vpp.ApiStream.SendMsg(&vlib.CliInband{Cmd: cmd}))
	msg, err := vpp.ApiStream.RecvMsg()
	AssertNil(err)
	reply, ok := msg.(*vlib.CliInbandReply)
	AssertEqual(true, ok, "CLI API returned %T", msg)
	AssertEqual(int32(0), reply.Retval, "CLI API failed: %s", reply.Reply)
	out := reply.Reply
	match := tcpDelayedCleanupPoolIndexRE.FindStringSubmatch(out)
	if match == nil {
		return "", out
	}
	return match[1], out
}

func tcpDelayedCleanupExpectHTTP200(conn net.Conn, label string) {
	AssertNil(conn.SetDeadline(time.Now().Add(2 * time.Second)))
	_, err := conn.Write([]byte("GET /show/version HTTP/1.1\r\nHost: vpp\r\nConnection: close\r\n\r\n"))
	AssertNil(err, "%s write failed", label)
	status, err := bufio.NewReader(conn).ReadString('\n')
	AssertNil(err, "%s read failed", label)
	AssertContains(status, " 200 ", "%s HTTP response: %q", label, status)
}

// TcpDelayedCleanupResetSurvivorTest checks that deferred cleanup of an old
// connection does not reset a later, unrelated TCP connection. TLS is not involved.
func TcpDelayedCleanupResetSurvivorTest(s *TcpHarnessSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientIP := net.ParseIP(s.Interfaces.Server.Host.Ip4AddressString()).To4()
	serverIP := net.ParseIP(s.Interfaces.Server.Ip4AddressString()).To4()
	AssertNotNil(clientIP)
	AssertNotNil(serverIP)
	serverPort64, err := strconv.ParseUint(s.Ports.Port1, 10, 16)
	AssertNil(err)
	serverPort := uint16(serverPort64)
	rawPort := s.GeneratePortAsInt()
	victimPort := s.GeneratePortAsInt()

	out := serverVpp.Vppctl("http cli server http1-only uri http://%s:%d",
		serverIP.String(), serverPort)
	AssertNotContains(strings.ToLower(out), "error", out)

	defer func() {
		AssertEmpty(serverVpp.Vppctl("http cli server listener del uri http://%s:%d",
			serverIP.String(), serverPort))
	}()
	serverAddress := net.JoinHostPort(serverIP.String(), strconv.Itoa(int(serverPort)))
	baseline, err := net.DialTimeout("tcp4", serverAddress, 500*time.Millisecond)
	AssertNil(err, "baseline TCP connect failed")
	time.Sleep(250 * time.Millisecond)
	tcpDelayedCleanupExpectHTTP200(baseline, "baseline")
	AssertNil(baseline.Close())
	// Let any baseline cleanup finish before testing the indexed cleanup.
	time.Sleep(200 * time.Millisecond)

	// A raw SYN normally makes Linux emit a RST for the unmatched SYN-ACK.
	// Suppress only kernel RSTs for this raw tuple; our packets use TTL 66.
	table := "hst_tcp_delayed_cleanup"
	AssertNil(tcpDelayedCleanupNft("add", "table", "ip", table))
	defer func() {
		if err := tcpDelayedCleanupNft("delete", "table", "ip", table); err != nil {
			Log("failed to remove temporary nft table: %v", err)
		}
	}()
	AssertNil(tcpDelayedCleanupNft("add", "chain", "ip", table, "output",
		"{ type filter hook output priority -150; policy accept; }"))
	AssertNil(tcpDelayedCleanupNft("add", "rule", "ip", table, "output",
		"ip", "saddr", clientIP.String(), "ip", "daddr", serverIP.String(),
		"ip", "ttl", "!=", "66", "tcp", "sport", strconv.Itoa(int(rawPort)),
		"tcp", "dport", strconv.Itoa(int(serverPort)),
		"tcp", "flags", "&", "rst", "==", "rst", "drop"))

	fd, err := tcpharness.OpenIPv4PacketSocket(s.Interfaces.Server.Host.Name())
	AssertNil(err)
	defer unix.Close(fd)

	const firstISN uint32 = 1000000
	tcpDelayedCleanupSendTCP(clientIP, serverIP, rawPort, serverPort, firstISN, 0, tcpDelayedCleanupSyn)
	firstServerISN, ok := tcpDelayedCleanupTryCaptureServerControl(fd, serverIP, clientIP,
		serverPort, rawPort, firstISN+1, true, false, 2*time.Second)
	AssertEqual(true, ok, "first SYN-ACK missing")

	oldIndex, oldSession := tcpDelayedCleanupPoolIndex(serverVpp, clientIP, rawPort)
	AssertNotEmpty(oldIndex, "first SYN_RCVD TCP pool index missing: %s", oldSession)
	Log("first raw connection TCP pool index %s", oldIndex)

	// FIN with the third handshake ACK enters TIME_WAIT and queues cleanup
	// for this index. A new SYN for the same tuple deletes that old session.
	finSent := time.Now()
	tcpDelayedCleanupSendTCP(clientIP, serverIP, rawPort, serverPort,
		firstISN+1, firstServerISN+1, tcpDelayedCleanupFinAck)
	_, finAck := tcpDelayedCleanupTryCaptureServerControl(fd, serverIP, clientIP,
		serverPort, rawPort, firstISN+2, false, true, 50*time.Millisecond)
	AssertEqual(true, finAck, "server FIN-ACK missing; TIME_WAIT transition not observed")
	const secondISN uint32 = firstISN + 100001
	tcpDelayedCleanupSendTCP(clientIP, serverIP, rawPort, serverPort, secondISN, 0, tcpDelayedCleanupSyn)
	secondServerISN, secondSynAck := tcpDelayedCleanupTryCaptureServerControl(fd, serverIP, clientIP,
		serverPort, rawPort, secondISN+1, true, false, 15*time.Millisecond)
	Log("second same-tuple SYN-ACK observed: %v", secondSynAck)
	if secondSynAck {
		tcpDelayedCleanupSendTCP(clientIP, serverIP, rawPort, serverPort,
			secondISN+1, secondServerISN+1, tcpDelayedCleanupRstAck)
		time.Sleep(2 * time.Millisecond)
	}

	// An ordinary socket on a different local port must take the freed slot
	// before the first connection's 100 ms cleanup request expires.
	dialer := net.Dialer{
		Timeout:   500 * time.Millisecond,
		LocalAddr: &net.TCPAddr{IP: clientIP, Port: int(victimPort)},
	}
	victim, err := dialer.Dial("tcp4", net.JoinHostPort(serverIP.String(),
		strconv.Itoa(int(serverPort))))
	AssertNil(err, "victim TCP connect failed")
	defer victim.Close()
	connectedAfterFin := time.Since(finSent)
	Log("victim connected %v after FIN; querying TCP pool index", connectedAfterFin)
	AssertLessThan(connectedAfterFin, 100*time.Millisecond,
		"victim connected after the delayed cleanup window: %v", connectedAfterFin)

	victimIndex, victimSession := tcpDelayedCleanupPoolIndex(serverVpp, clientIP, victimPort)
	queriedAfterFin := time.Since(finSent)
	Log("victim TCP pool index %s queried %v after FIN", victimIndex, queriedAfterFin)
	AssertLessThan(queriedAfterFin, 100*time.Millisecond,
		"victim pool index query ended after delayed cleanup window: %v", queriedAfterFin)
	AssertNotEmpty(victimIndex, "victim session missing: %s", victimSession)
	if oldIndex == victimIndex {
		Log("reused TCP pool index %s for different tuple after %v",
			oldIndex, connectedAfterFin)
	} else {
		Log("victim used a different TCP pool index: old=%s victim=%s",
			oldIndex, victimIndex)
	}

	// The pending cleanup should expire before the victim sends its request.
	if remaining := time.Until(finSent.Add(250 * time.Millisecond)); remaining > 0 {
		time.Sleep(remaining)
	}
	Log("probing victim %v after FIN", time.Since(finSent))
	tcpDelayedCleanupExpectHTTP200(victim, "victim after pending cleanup")

}
