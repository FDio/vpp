// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <vlib/vlib.h>
#include <vnet/tcp/tcp.h>
#include <vnet/session_quality/session_quality.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/sasc_funcs.h>
#include <sasc/export.h>
// Remove circular dependency - don't include packet_stats.h here

/* Public API for the flow-quality node (called on each TCP packet) */
void fq_tcp_on_packet(vlib_main_t *vm, vlib_buffer_t *b, u8 dir, tcp_header_t *th, u32 session_index, f64 now);

/* Register the TCP scorer; call this once from flow-quality init */
void fq_tcp_register_scorer(void);

/* Access overlay state (optional helpers if you need them elsewhere) */
// session_quality_tcp_data_t* fq_tcp_state_at(u32 session_index);

/* Optional: memory usage reporting */
u64 fq_tcp_memory_usage(void);

/* RTT analysis helpers for external use */
f64 fq_tcp_get_rtt_mean(u32 session_index, u8 direction);
f64 fq_tcp_get_rtt_stddev(u32 session_index, u8 direction);
f64 fq_tcp_get_rtt_asymmetry(u32 session_index);
