package hst

import "testing"

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
	// interface name in an ip/neighbor log message, noise
	tbInterfaceNameFormat = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd3",
		"_vec_add + 0x159",
		"do_percent + 0xcb4",
		"va_format + 0xb8",
		"format + 0x91",
		"format_vnet_sw_interface_name + 0x14c",
		"do_percent + 0xe83",
		"va_format + 0xb8",
		"format + 0x91",
		"format_vnet_sw_if_index_name + 0x110",
		"do_percent + 0xe83",
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
		{name: "interface name in log message", traceback: tbInterfaceNameFormat, noise: true},
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
		{Count: 1, Size: 32, Sample: "interface name in log message", Traceback: tbInterfaceNameFormat},
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
