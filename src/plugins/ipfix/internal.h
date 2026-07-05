/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#pragma once

#include <ipfix/ipfix.h>
#include <ipfix/ipfix_classify.h>

extern ipfix_main_t ipfix_main;
extern vlib_node_registration_t ipfix_process_node;

u8 *ipfix_rewrite_generic_callback (ipfix_exporter_t *exp, ipfix_report_t *report,
				    u16 collector_port, ipfix_report_element_t *elements,
				    u32 n_elements, u32 *stream_index);

int ipfix_report_add_del (ipfix_exporter_t *exp, ipfix_report_add_del_args_t *args,
			  u16 *template_id);

clib_error_t *ipfix_report_add_del_error_to_clib_error (int error);

void ipfix_reports_reset (ipfix_exporter_t *exp);
void ipfix_stream_reset (ipfix_exporter_t *exp, u32 stream_index);
int ipfix_stream_change (ipfix_exporter_t *exp, u32 old_domain_id, u16 old_src_port,
			 u32 new_domain_id, u16 new_src_port);

ipfix_exporter_t *ipfix_exporter_lookup (const ip_address_t *ipfix_collector);

vlib_buffer_t *ipfix_get_buffer (vlib_main_t *vm, ipfix_exporter_t *exp, ipfix_report_t *report,
				 clib_thread_index_t thread_index);

void ipfix_send_buffer (vlib_main_t *vm, ipfix_exporter_t *exp, ipfix_report_t *report,
			ipfix_stream_t *stream, clib_thread_index_t thread_index,
			vlib_buffer_t *buffer);
