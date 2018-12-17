 /*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/mfib/mfib_types.h>

#include <vnet/ip/ip.h>

/**
 * String names for each flag
 */
static const char *mfib_flag_names[] = MFIB_ENTRY_NAMES_SHORT;
static const char *mfib_flag_names_long[] = MFIB_ENTRY_NAMES_LONG;

static const char *mfib_itf_flag_long_names[] = MFIB_ITF_NAMES_LONG;
static const char *mfib_itf_flag_names[] = MFIB_ITF_NAMES_SHORT;

int
mfib_prefix_is_cover (const mfib_prefix_t *p1,
                      const mfib_prefix_t *p2)
{
    if (!ip46_address_is_equal(&p1->fp_src_addr, &p2->fp_src_addr))
        return (0);

    switch (p1->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_destination_matches_route(&ip4_main,
					      &p1->fp_grp_addr.ip4,
					      &p2->fp_grp_addr.ip4,
					      p1->fp_len));
    case FIB_PROTOCOL_IP6:
	return (ip6_destination_matches_route(&ip6_main,
					      &p1->fp_grp_addr.ip6,
					      &p2->fp_grp_addr.ip6,
					      p1->fp_len));
    case FIB_PROTOCOL_MPLS:
	break;
    }
    return (0);
}

int
mfib_prefix_is_host (const mfib_prefix_t *pfx)
{
    switch (pfx->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (64 == pfx->fp_len);
    case FIB_PROTOCOL_IP6:
	return (256 == pfx->fp_len);
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
	break;
    }
    return (0);
}

fib_forward_chain_type_t
mfib_forw_chain_type_from_dpo_proto (dpo_proto_t proto)
{
    switch (proto)
    {
    case DPO_PROTO_IP4:
	return (FIB_FORW_CHAIN_TYPE_MCAST_IP4);
    case DPO_PROTO_IP6:
	return (FIB_FORW_CHAIN_TYPE_MCAST_IP6);
    case DPO_PROTO_MPLS:
    case DPO_PROTO_ETHERNET:
    case DPO_PROTO_NSH:
    case DPO_PROTO_BIER:
        break;
    }
    ASSERT(0);
    return (FIB_FORW_CHAIN_TYPE_MCAST_IP4);
}

fib_forward_chain_type_t
mfib_forw_chain_type_from_fib_proto (fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (FIB_FORW_CHAIN_TYPE_MCAST_IP4);
    case FIB_PROTOCOL_IP6:
	return (FIB_FORW_CHAIN_TYPE_MCAST_IP6);
    case FIB_PROTOCOL_MPLS:
        break;
    }
    ASSERT(0);
    return (FIB_FORW_CHAIN_TYPE_MCAST_IP4);
}

u8 *
format_mfib_prefix (u8 * s, va_list * args)
{
    mfib_prefix_t *fp = va_arg (*args, mfib_prefix_t *);

    /*
     * protocol specific so it prints ::/0 correctly.
     */
    switch (fp->fp_proto)
    {
    case FIB_PROTOCOL_IP6:
    {
        ip6_address_t p6 = fp->fp_grp_addr.ip6;
        u32 len = (fp->fp_len > 128 ? 128 : fp->fp_len);

        ip6_address_mask(&p6, &(ip6_main.fib_masks[len]));

        if (ip6_address_is_zero(&fp->fp_src_addr.ip6))
        {
            s = format(s, "(*, ");
        }
        else
        {
            s = format (s, "(%U, ", format_ip6_address, &fp->fp_src_addr.ip6);
        }
        s = format (s, "%U", format_ip6_address, &p6);
        s = format (s, "/%d)", len);
        break;
    }
    case FIB_PROTOCOL_IP4:
    {
        ip4_address_t p4 = fp->fp_grp_addr.ip4;
        u32 len = (fp->fp_len > 32 ? 32 : fp->fp_len);

        p4.as_u32 &= ip4_main.fib_masks[len];

        if (0 == fp->fp_src_addr.ip4.as_u32)
        {
            s = format(s, "(*, ");
        }
        else
        {
            s = format (s, "(%U, ", format_ip4_address, &fp->fp_src_addr.ip4);
        }
        s = format (s, "%U", format_ip4_address, &p4);
        s = format (s, "/%d)", len);
        break;
    }
    case FIB_PROTOCOL_MPLS:
        break;
    }

    return (s);
}

u8 *
format_mfib_entry_flags (u8 * s, va_list * args)
{
    mfib_entry_attribute_t attr;
    mfib_entry_flags_t flags;

    flags = va_arg (*args, mfib_entry_flags_t);

    if (MFIB_ENTRY_FLAG_NONE != flags) {
        s = format(s, " flags:");
        FOR_EACH_MFIB_ATTRIBUTE(attr) {
            if ((1<<attr) & flags) {
                s = format (s, "%s,", mfib_flag_names_long[attr]);
            }
        }
    }

    return (s);
}

u8 *
format_mfib_itf_flags (u8 * s, va_list * args)
{
    mfib_itf_attribute_t attr;
    mfib_itf_flags_t flags;

    flags = va_arg (*args, mfib_itf_flags_t);

    FOR_EACH_MFIB_ITF_ATTRIBUTE(attr) {
        if ((1<<attr) & flags) {
            s = format (s, "%s,", mfib_itf_flag_long_names[attr]);
        }
    }

    return (s);
}

uword
unformat_mfib_itf_flags (unformat_input_t * input,
                         va_list * args)
{
    mfib_itf_flags_t old, *iflags = va_arg (*args, mfib_itf_flags_t*);
    mfib_itf_attribute_t attr;

    old = *iflags;
    FOR_EACH_MFIB_ITF_ATTRIBUTE(attr) {
        if (unformat (input, mfib_itf_flag_long_names[attr]))
            *iflags |= (1 << attr);
    }
    FOR_EACH_MFIB_ITF_ATTRIBUTE(attr) {
        if (unformat (input, mfib_itf_flag_names[attr]))
            *iflags |= (1 << attr);
    }

    return (old == *iflags ? 0 : 1);
}

uword
unformat_mfib_entry_flags (unformat_input_t * input,
                           va_list * args)
{
    mfib_entry_flags_t old, *eflags = va_arg (*args, mfib_entry_flags_t*);
    mfib_entry_attribute_t attr;

    old = *eflags;
    FOR_EACH_MFIB_ATTRIBUTE(attr) {
        if (unformat (input, mfib_flag_names_long[attr]))
            *eflags |= (1 << attr);
    }
    FOR_EACH_MFIB_ATTRIBUTE(attr) {
        if (unformat (input, mfib_flag_names[attr]))
            *eflags |= (1 << attr);
    }

    return (old == *eflags ? 0 : 1);
}

clib_error_t *
mfib_show_route_flags (vlib_main_t * vm,
                       unformat_input_t * main_input,
                       vlib_cli_command_t * cmd)
{
    mfib_entry_attribute_t attr;

    FOR_EACH_MFIB_ATTRIBUTE(attr) {
        vlib_cli_output(vm, "%s = %s",
                        mfib_flag_names[attr],
                        mfib_flag_names_long[attr]);
    }

    return (NULL);
}

/*?
 * This command displays the set of supported flags applicable to an MFIB route
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mfib_route_flags_command, static) =
{
  .path = "show mfib route flags",
  .short_help = "Flags applicable to an MFIB route",
  .function = mfib_show_route_flags,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
mfib_show_itf_flags (vlib_main_t * vm,
                     unformat_input_t * main_input,
                     vlib_cli_command_t * cmd)
{
    mfib_itf_attribute_t attr;

    FOR_EACH_MFIB_ITF_ATTRIBUTE(attr) {
        vlib_cli_output(vm, "%s = %s",
                        mfib_itf_flag_names[attr],
                        mfib_itf_flag_long_names[attr]);
    }

    return (NULL);
}

/*?
 * This command displays the set of supported flags applicable to an MFIB interface
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mfib_itf_flags_command, static) =
{
  .path = "show mfib itf flags",
  .short_help = "Flags applicable to an MFIB interfaces",
  .function = mfib_show_itf_flags,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */
