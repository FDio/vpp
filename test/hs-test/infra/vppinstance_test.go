package hst

import "testing"

// Tracebacks as they appear in the mem-leak report, deepest frame first.
var (
	// per worker session tx scratch vector, noise
	tbSessionTxVecValidate = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_resize_internal + 0xd4",
		"_vec_validate + 0x112",
		"session_tx_burst_inline + 0x2bc",
		"session_tx_burst_stream + 0x5a",
		"tcp_session_send_data + 0x264",
		"tcp_session_custom_tx + 0x118",
		"transport_custom_tx + 0x38",
		"session_tx_send + 0x25e",
		"session_tx_dispatch + 0x73",
		"session_event_dispatch_io + 0xe9",
		"session_queue_node_fn + 0x118b",
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
	tbSessionTxFifoPeek = []string{
		"_vec_realloc_internal + 0x100",
		"_pool_get + 0x1b7",
		"rb_tree_add_custom + 0x6f",
		"f_update_ooo_deq + 0xf2",
		"svm_fifo_peek + 0xff",
		"session_tx_stream_copy + 0x55",
		"session_tx_fill_buffer + 0xea",
		"session_tx_burst_inline + 0x778",
		"session_tx_burst_stream + 0x5a",
		"tcp_session_send_data + 0x264",
		"tcp_session_custom_tx + 0x118",
		"transport_custom_tx + 0x38",
	}
	// both pair frames present but not adjacent, must be reported
	tbPairNotAdjacent = []string{
		"_vec_realloc_internal + 0x100",
		"_vec_validate + 0x112",
		"_hash_set3 + 0x2a1",
		"session_tx_fill_buffer + 0xea",
		"session_tx_burst_inline + 0x778",
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
		"_vec_validate + 0x112",
		"session_tx_burst_inline + 0x2bc",
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
		{name: "pair on last two frames", traceback: tbPairAtCap, noise: true},
		{name: "deliberate leak", traceback: tbDeliberateLeak, noise: false},
		{name: "session tx fifo peek", traceback: tbSessionTxFifoPeek, noise: false},
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
		{Count: 1, Size: 64, Sample: "session tx fifo peek", Traceback: tbSessionTxFifoPeek},
		{Count: 1, Size: 32, Sample: "pair not adjacent", Traceback: tbPairNotAdjacent},
	}
	expected := []string{"deliberate leak", "session tx fifo peek", "pair not adjacent"}

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
