/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_format_h
#define included_npol_format_h

u8 *format_npol_interface (u8 *s, va_list *args);
u8 *format_npol_policy (u8 *s, va_list *args);
u8 *format_npol_ipset (u8 *s, va_list *args);
u8 *format_npol_rule (u8 *s, va_list *args);
uword unformat_npol_ipset_member (unformat_input_t *input, va_list *args);
uword unformat_npol_rule_entry (unformat_input_t *input, va_list *args);
uword unformat_npol_rule_action (unformat_input_t *input, va_list *args);
uword unformat_npol_rule_filter (unformat_input_t *input, va_list *args);
u8 *format_npol_rule_filter (u8 *s, va_list *args);
u8 *format_npol_action (u8 *s, va_list *args);

#endif