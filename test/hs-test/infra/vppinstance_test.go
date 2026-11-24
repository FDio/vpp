package hst

import (
	"strings"
	"testing"
)

// Tracebacks as they appear in the mem-leak report, deepest frame first.
var (
	// per worker session tx scratch vector, noise
	tbSessionTxVecValidate = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_vec_validate + 0x111",
		"session_tx_fifo_read_and_snd_i + 0x5cb",
		"session_tx_fifo_peek_and_snd + 0x32",
		"session_event_dispatch_io + 0x104",
		"session_queue_node_fn + 0xc69",
		"dispatch_node + 0x348",
		"vlib_main_or_worker_loop + 0x49f",
		"vlib_main + 0x678",
		"thread0 + 0x7c",
		"0x7c7143c6c6e3",
	}
	// per worker session event pool free indices, noise
	tbSessionEventPoolPut = []string{
		"_vec_add1",
		"_pool_put_index",
		"session_event_dispatch_io",
		"session_queue_node_fn",
	}
	// pool free indices, noise
	tbHttpCliSessionPoolPut = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_vec_add1 + 0xda",
		"_pool_put_index + 0x1e3",
		"hcs_session_free + 0x7f",
		"hcs_ts_cleanup_callback + 0xb2",
		"app_worker_flush_events_inline + 0x99f",
	}
	// CLI machinery serving the vppctl call that dumps the trace, noise
	tbUnixCli = []string{
		"_vec_alloc_internal + 0x11c",
		"_vec_resize + 0x6b",
		"unix_cli_read_ready + 0x166",
		"vlib_file_poll + 0x656",
		"vlib_main_or_worker_loop + 0x3b3",
		"vlib_main + 0x678",
		"thread0 + 0x7c",
	}
	// The November 22 leak job hit the frame cap before unix_cli_process_input.
	tbSaveMemoryTracePath = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_vec_add + 0x159",
		"do_percent + 0xaf6",
		"va_format + 0xb8",
		"format + 0x91",
		"save_memory_trace + 0xf1",
		"cli_dispatch + 0x23e",
		"vlib_cli_call_function + 0xc4",
		"vlib_cli_dispatch_sub_commands + 0xeae",
		"vlib_cli_dispatch_sub_commands + 0xbfe",
		"vlib_cli_input + 0x91",
	}
	tbSaveMemoryTraceFilename = []string{
		"_vec_alloc_internal + 0x11c",
		"_vec_dup + 0x83",
		"parse_string + 0x9a",
		"parse_value + 0x285",
		"parse_positional + 0x29",
		"parse_seq + 0x5f8",
		"cli_parse_line + 0x1da",
		"cli_dispatch + 0xe9",
		"vlib_cli_call_function + 0xc4",
		"vlib_cli_dispatch_sub_commands + 0xeae",
		"vlib_cli_dispatch_sub_commands + 0xbfe",
		"vlib_cli_input + 0x91",
	}
	// deliberate leak of 'test mem-leak', must always be reported. Note it has
	// _vec_validate right below leak_memory_fn, so a callee-only or unordered
	// rule would suppress it.
	tbDeliberateLeak = []string{
		"_vec_alloc_internal + 0x11c",
		"_vec_validate + 0x7b",
		"leak_memory_fn + 0x4e",
		"vlib_process_bootstrap + 0x5c",
	}
	// another path through the same caller, must be reported
	tbTcpSendAck = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_hash_set3 + 0x2a1",
		"vlib_buffer_alloc + 0x9f",
		"tcp_send_ack + 0x11d",
		"tcp_session_custom_tx + 0x2e2",
		"session_tx_fifo_read_and_snd_i + 0x494",
		"session_event_dispatch_io + 0x104",
	}
	// both pair frames present but not adjacent, must be reported
	tbPairNotAdjacent = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_validate + 0x111",
		"_hash_set3 + 0x2a1",
		"tcp_session_custom_tx + 0x2e2",
		"session_tx_fifo_read_and_snd_i + 0x494",
	}
	// pair on the last two frames still matches, the cap only hides what is past them
	tbPairAtCap = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_hash_set3 + 0x2a1",
		"hash_resize + 0x1b1",
		"_hash_create + 0x9c",
		"vlib_buffer_alloc + 0x9f",
		"session_tx_maybe_reschedule + 0x41",
		"dispatch_node + 0x348",
		"vlib_main + 0x678",
		"thread0 + 0x7c",
		"_vec_validate + 0x111",
		"session_tx_fifo_read_and_snd_i + 0x5cb",
	}
	// caller pushed past the cap, cannot match
	tbPairTruncated = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_vec_validate + 0x111",
	}
)

func TestMemTraceIsReportNoise(t *testing.T) {
	tests := []struct {
		name      string
		traceback []string
		noise     bool
	}{
		{name: "session tx scratch vector", traceback: tbSessionTxVecValidate, noise: true},
		{name: "session event pool put", traceback: tbSessionEventPoolPut, noise: true},
		{name: "HTTP CLI session pool put", traceback: tbHttpCliSessionPoolPut, noise: true},
		{name: "pool put with another caller", traceback: []string{"_vec_validate", "clib_bitmap_ori_notrim", "_pool_put_index", "session_free"}, noise: false},
		{name: "pool put with caller truncated", traceback: []string{"_vec_add1", "_pool_put_index + 0x1e3"}, noise: false},
		{name: "pool get", traceback: []string{"_vec_realloc_internal", "_pool_get", "session_alloc"}, noise: false},
		{name: "unix cli", traceback: tbUnixCli, noise: true},
		{name: "formatted trace dump path", traceback: tbSaveMemoryTracePath, noise: true},
		{name: "format under another caller", traceback: []string{"format + 0x91", "show_memory_usage"}, noise: false},
		{name: "parsed filename", traceback: tbSaveMemoryTraceFilename, noise: false},
		{name: "pair on last two frames", traceback: tbPairAtCap, noise: true},
		{name: "deliberate leak", traceback: tbDeliberateLeak, noise: false},
		{name: "tcp send ack", traceback: tbTcpSendAck, noise: false},
		{name: "pair not adjacent", traceback: tbPairNotAdjacent, noise: false},
		{name: "pair truncated", traceback: tbPairTruncated, noise: false},
		{name: "empty traceback", traceback: nil, noise: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trace := VppMemTrace{Count: 1, Size: 32, Sample: test.name, Traceback: test.traceback}
			noise, match := memTraceIsReportNoise(trace)
			if noise != test.noise {
				t.Fatalf("memTraceIsReportNoise(%q) = %t (%q), expected %t",
					test.name, noise, match, test.noise)
			}
			if noise && match == "" {
				t.Fatalf("memTraceIsReportNoise(%q) suppressed without naming a match", test.name)
			}
		})
	}
}

func TestMemTracesSuppressReportNoise(t *testing.T) {
	traces := []VppMemTrace{
		{Count: 1, Size: 192, Sample: "session tx scratch vector", Traceback: tbSessionTxVecValidate},
		{Count: 1, Size: 4112, Sample: "unix cli", Traceback: tbUnixCli},
		{Count: 1, Size: 112, Sample: "deliberate leak", Traceback: tbDeliberateLeak},
		{Count: 1, Size: 64, Sample: "tcp send ack", Traceback: tbTcpSendAck},
		{Count: 1, Size: 32, Sample: "pair not adjacent", Traceback: tbPairNotAdjacent},
	}
	expected := []string{"deliberate leak", "tcp send ack", "pair not adjacent"}

	filtered := memTracesSuppressReportNoise(traces)
	if len(filtered) != len(expected) {
		t.Fatalf("memTracesSuppressReportNoise() kept %d trace(s), expected %d",
			len(filtered), len(expected))
	}
	for i := range expected {
		if filtered[i].Sample != expected[i] {
			t.Fatalf("memTracesSuppressReportNoise()[%d] = %q, expected %q",
				i, filtered[i].Sample, expected[i])
		}
	}
}

func TestMemLeakReportSnapshotAllocations(t *testing.T) {
	first := []VppMemTrace{
		{Count: 1, Size: 32, Sample: "0x1000", Traceback: tbSaveMemoryTraceFilename},
	}
	second := []VppMemTrace{
		{Count: 1, Size: 32, Sample: "0x2000", Traceback: tbSaveMemoryTraceFilename},
		{Count: 1, Size: 32, Sample: "0x3000", Traceback: tbSaveMemoryTracePath},
	}
	report, bytes, count := memLeakReport(first, second)
	if bytes != 0 || count != 0 || report != "" {
		t.Fatalf("snapshot allocations reported as leaks: %d bytes in %d allocations\n%s", bytes, count, report)
	}

	second[0].Count = 2
	second[0].Size = 64
	second = append(second, VppMemTrace{Count: 1, Size: 112, Sample: "0x4000", Traceback: tbDeliberateLeak})
	report, bytes, count = memLeakReport(first, second)
	if bytes != 144 || count != 2 || !strings.Contains(report, "grow 32 byte(s)") ||
		!strings.Contains(report, "leak of 112 byte(s)") {
		t.Fatalf("expected parser growth and the deliberate leak, got %d bytes in %d allocations\n%s", bytes, count, report)
	}
}

func TestMemLeakReportReusedFilenameSample(t *testing.T) {
	first := []VppMemTrace{
		{Count: 1, Size: 32, Sample: "0x1000", Traceback: tbSaveMemoryTraceFilename},
	}
	second := []VppMemTrace{
		{Count: 1, Size: 32, Sample: "0x2000", Traceback: tbSaveMemoryTraceFilename},
		{Count: 1, Size: 32, Sample: "0x1000", Traceback: tbDeliberateLeak},
	}
	report, bytes, count := memLeakReport(first, second)
	if bytes != 32 || count != 1 || !strings.Contains(report, "leak_memory_fn") {
		t.Fatalf("expected the allocation at the reused address, got %d bytes in %d allocations\n%s",
			bytes, count, report)
	}
}
