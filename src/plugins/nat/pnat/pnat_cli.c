/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vppinfra/clib_error.h>
#include <vppinfra/pool.h>
#include "pnat.h"

/*
 * This file contains the handlers for the (unsupported) VPP debug CLI.
 */
u8 *format_pnat_match_tuple(u8 *s, va_list *args) {
    pnat_match_tuple_t *t = va_arg(*args, pnat_match_tuple_t *);
    s = format(s, "{");
    if (t->mask & PNAT_SA)
        s = format(s, "%U", format_ip4_address, &t->src);
    else
        s = format(s, "*");
    if (t->mask & PNAT_SPORT)
        s = format(s, ":%u,", t->sport);
    else
        s = format(s, ":*,");
    if (t->proto > 0)
        s = format(s, "%U,", format_ip_protocol, t->proto);
    else
        s = format(s, "*,");
    if (t->mask & PNAT_DA)
        s = format(s, "%U", format_ip4_address, &t->dst);
    else
        s = format(s, "*");
    if (t->mask & PNAT_DPORT)
        s = format(s, ":%u", t->dport);
    else
        s = format(s, ":*");
    s = format(s, "}");
    return s;
}
u8 *format_pnat_rewrite_tuple(u8 *s, va_list *args) {
    pnat_rewrite_tuple_t *t = va_arg(*args, pnat_rewrite_tuple_t *);
    s = format(s, "{");
    if (t->mask & PNAT_SA)
        s = format(s, "%U", format_ip4_address, &t->src);
    else
        s = format(s, "*");
    if (t->mask & PNAT_SPORT)
        s = format(s, ":%u,", t->sport);
    else
        s = format(s, ":*,");
    if (t->mask & PNAT_DA)
        s = format(s, "%U", format_ip4_address, &t->dst);
    else
        s = format(s, "*");
    if (t->mask & PNAT_DPORT)
        s = format(s, ":%u", t->dport);
    else
        s = format(s, ":*");
    if (t->mask & PNAT_COPY_BYTE)
        s = format(s, " copy byte@[%d->%d]", t->from_offset, t->to_offset);
    if (t->mask & PNAT_CLEAR_BYTE)
        s = format(s, " clear byte@[%d]", t->clear_offset);
    s = format(s, "}");
    return s;
}

u8 *format_pnat_translation(u8 *s, va_list *args) {
    u32 index = va_arg(*args, u32);
    pnat_translation_t *t = va_arg(*args, pnat_translation_t *);
    s = format(s, "[%d] match: %U rewrite: %U", index, format_pnat_match_tuple,
               &t->match, format_pnat_rewrite_tuple, &t->rewrite);
    return s;
}

static u8 *format_pnat_mask(u8 *s, va_list *args) {
    pnat_mask_t t = va_arg(*args, pnat_mask_t);
    if (t & PNAT_SA)
        s = format(s, "SA ");
    if (t & PNAT_SPORT)
        s = format(s, "SP ");
    if (t & PNAT_DA)
        s = format(s, "DA ");
    if (t & PNAT_DPORT)
        s = format(s, "DP");
    return s;
}

static u8 *format_pnat_interface(u8 *s, va_list *args) {
    pnat_interface_t *interface = va_arg(*args, pnat_interface_t *);
    s = format(s, "sw_if_index: %d", interface->sw_if_index);
    if (interface->enabled[PNAT_IP4_INPUT]) {
        s = format(s, " input mask: %U", format_pnat_mask,
                   interface->lookup_mask[PNAT_IP4_INPUT]);
    }
    if (interface->enabled[PNAT_IP4_OUTPUT]) {
        s = format(s, " output mask: %U", format_pnat_mask,
                   interface->lookup_mask[PNAT_IP4_OUTPUT]);
    }
    return s;
}

uword unformat_pnat_match_tuple(unformat_input_t *input, va_list *args) {
    pnat_match_tuple_t *t = va_arg(*args, pnat_match_tuple_t *);
    u32 dport, sport;
    while (1) {
        if (unformat(input, "src %U", unformat_ip4_address, &t->src))
            t->mask |= PNAT_SA;
        else if (unformat(input, "dst %U", unformat_ip4_address, &t->dst))
            t->mask |= PNAT_DA;
        else if (unformat(input, "sport %d", &sport)) {
            if (sport == 0 || sport > 65535)
                return 0;
            t->mask |= PNAT_SPORT;
            t->sport = sport;
        } else if (unformat(input, "dport %d", &dport)) {
            if (dport == 0 || dport > 65535)
                return 0;
            t->mask |= PNAT_DPORT;
            t->dport = dport;
        } else if (unformat(input, "proto %U", unformat_ip_protocol, &t->proto))
            ;
        else
            break;
    }
    return 1;
}

uword unformat_pnat_rewrite_tuple(unformat_input_t *input, va_list *args) {
    pnat_rewrite_tuple_t *t = va_arg(*args, pnat_rewrite_tuple_t *);
    u32 dport, sport;
    u32 to_offset, from_offset, clear_offset;

    while (1) {
        if (unformat(input, "src %U", unformat_ip4_address, &t->src))
            t->mask |= PNAT_SA;
        else if (unformat(input, "dst %U", unformat_ip4_address, &t->dst))
            t->mask |= PNAT_DA;
        else if (unformat(input, "sport %d", &sport)) {
            if (sport == 0 || sport > 65535)
                return 0;
            t->mask |= PNAT_SPORT;
            t->sport = sport;
        } else if (unformat(input, "dport %d", &dport)) {
            if (dport == 0 || dport > 65535)
                return 0;
            t->mask |= PNAT_DPORT;
            t->dport = dport;
        } else if (unformat(input, "copy-byte-at-offset %d %d", &from_offset,
                            &to_offset)) {
            if (from_offset == to_offset || to_offset > 255 ||
                from_offset > 255)
                return 0;
            t->mask |= PNAT_COPY_BYTE;
            t->from_offset = from_offset;
            t->to_offset = to_offset;
        } else if (unformat(input, "clear-byte-at-offset %d", &clear_offset)) {
            if (clear_offset > 255)
                return 0;
            t->mask |= PNAT_CLEAR_BYTE;
            t->clear_offset = clear_offset;
        } else
            break;
    }
    return 1;
}

static clib_error_t *set_pnat_translation_command_fn(vlib_main_t *vm,
                                                     unformat_input_t *input,
                                                     vlib_cli_command_t *cmd) {
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    bool in = false, out = false;
    bool match_set = false, rewrite_set = false;
    bool add = true;
    u32 sw_if_index = ~0;
    pnat_match_tuple_t match = {0};
    pnat_rewrite_tuple_t rewrite = {0};

    /* Get a line of input. */
    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "match %U", unformat_pnat_match_tuple, &match))
            match_set = true;
        else if (unformat(line_input, "rewrite %U", unformat_pnat_rewrite_tuple,
                          &rewrite))
            rewrite_set = true;
        else if (unformat(line_input, "interface %U",
                          unformat_vnet_sw_interface, vnet_get_main(),
                          &sw_if_index))
            ;
        else if (unformat(line_input, "in")) {
            in = true;
        } else if (unformat(line_input, "out")) {
            out = true;
        } else if (unformat(line_input, "del")) {
            add = false;
        } else {
            error = clib_error_return(0, "unknown input `%U'",
                                      format_unformat_error, line_input);
            goto done;
        }
    }
    if (sw_if_index == ~0) {
        error = clib_error_return(0, "interface is required `%U'",
                                  format_unformat_error, line_input);
        goto done;
    }
    if ((in && out) || (!in && !out)) {
        error = clib_error_return(0, "in or out is required `%U'",
                                  format_unformat_error, line_input);
        goto done;
    }
    if (!match_set) {
        error = clib_error_return(0, "missing parameter: match `%U'",
                                  format_unformat_error, line_input);
        goto done;
    }
    if (!rewrite_set) {
        error = clib_error_return(0, "missing parameter: rewrite `%U'",
                                  format_unformat_error, line_input);
        goto done;
    }

    if ((match.dport || match.sport) &&
        (match.proto != 17 && match.proto != 6)) {
        error = clib_error_return(0, "missing protocol (TCP|UDP): match `%U'",
                                  format_unformat_error, line_input);
        goto done;
    }
    pnat_attachment_point_t attachment = in ? PNAT_IP4_INPUT : PNAT_IP4_OUTPUT;

    if (add) {
        u32 binding_index;
        int rv = pnat_binding_add(&match, &rewrite, &binding_index);
        if (rv) {
            error = clib_error_return(0, "Adding binding failed %d", rv);
            goto done;
        }
        rv = pnat_binding_attach(sw_if_index, attachment, binding_index);
        if (rv) {
            pnat_binding_del(binding_index);
            error = clib_error_return(
                0, "Attaching binding to interface failed %d", rv);
            goto done;
        }
    } else {
        /* Lookup binding and lookup interface if both exists proceed with
         * delete */
        u32 binding_index = pnat_flow_lookup(sw_if_index, attachment, &match);
        if (binding_index == ~0) {
            error = clib_error_return(0, "Binding does not exist");
            goto done;
        }
        pnat_attachment_point_t attachment =
            in ? PNAT_IP4_INPUT : PNAT_IP4_OUTPUT;
        int rv = pnat_binding_detach(sw_if_index, attachment, binding_index);
        if (rv) {
            error = clib_error_return(0, "Detaching binding failed %d %d",
                                      binding_index, rv);
            goto done;
        }
        rv = pnat_binding_del(binding_index);
        if (rv) {
            error = clib_error_return(0, "Deleting translation failed %d %d",
                                      binding_index, rv);
            goto done;
        }
    }

done:
    unformat_free(line_input);

    return error;
}

VLIB_CLI_COMMAND(set_pnat_translation_command, static) = {
    .path = "set pnat translation",
    .short_help = "set pnat translation interface <name> match <5-tuple> "
                  "rewrite <tuple> {in|out} [del]",
    .function = set_pnat_translation_command_fn,
};

static clib_error_t *
show_pnat_translations_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *cmd) {
    pnat_main_t *pm = &pnat_main;
    pnat_translation_t *s;
    clib_error_t *error = 0;

    /* Get a line of input. */
    pool_foreach(s, pm->translations) {
        vlib_cli_output(vm, "%U", format_pnat_translation, s - pm->translations,
                        s);
    }
    return error;
}

VLIB_CLI_COMMAND(show_pnat_translations_command, static) = {
    .path = "show pnat translations",
    .short_help = "show pnat translations",
    .function = show_pnat_translations_command_fn,
};

static clib_error_t *show_pnat_interfaces_command_fn(vlib_main_t *vm,
                                                     unformat_input_t *input,
                                                     vlib_cli_command_t *cmd) {
    pnat_main_t *pm = &pnat_main;
    pnat_interface_t *interface;
    clib_error_t *error = 0;

    /* Get a line of input. */
    pool_foreach(interface, pm->interfaces) {
        vlib_cli_output(vm, "%U", format_pnat_interface, interface);
    }
    return error;
}

VLIB_CLI_COMMAND(show_pnat_interfaces_command, static) = {
    .path = "show pnat interfaces",
    .short_help = "show pnat interfaces",
    .function = show_pnat_interfaces_command_fn,
};
