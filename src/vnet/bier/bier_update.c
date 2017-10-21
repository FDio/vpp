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

#include <vnet/vnet.h>
#include <vnet/mpls/mpls.h>

#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_update.h>

clib_error_t *
vnet_bier_table_cmd (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
    u32 hdr_len, local_label;
    clib_error_t * error = 0;
    bier_table_id_t bti = {
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };
    u32 is_add = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "del")) {
            is_add = 0;
        } else if (unformat (input, "add")) {
            is_add = 1;
        } else if (unformat (input, "sd %d", &bti.bti_sub_domain)) {
        } else if (unformat (input, "set %d", &bti.bti_set)) {
        } else if (unformat (input, "bsl %d", &hdr_len)) {
        } else if (unformat (input, "mpls %d", &local_label)) {
        } else {
            error = unformat_parse_error (input);
            goto done;
        }
    }

    bti.bti_hdr_len = bier_hdr_bit_len_to_id(hdr_len);
    // FIXME
    bti.bti_type = BIER_TABLE_MPLS_SPF;

    if (is_add)
    {
        bier_table_add_or_lock(&bti, local_label);
    }
    else
    {
        bier_table_unlock(&bti);
    }

done:
    return (error);
}

VLIB_CLI_COMMAND (bier_table_command) = {
  .path = "bier table",
  .short_help = "Add/delete BIER Tables",
  .function = vnet_bier_table_cmd,
};

clib_error_t *
vnet_bier_route_cmd (vlib_main_t * vm,
                     unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
    clib_error_t * error = NULL;
    fib_route_path_t brp = {
        .frp_flags = FIB_ROUTE_PATH_BIER_FMASK,
    };
    bier_table_id_t bti = {
    };
    mpls_label_t out_label;
    bier_bp_t bp;
    u32 hdr_len;
    u32 add = 1;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "del")) {
            add = 0;
        } else if (unformat (input, "sd %d", &bti.bti_sub_domain)) {
        } else if (unformat (input, "set %d", &bti.bti_set)) {
        } else if (unformat (input, "bsl %d", &hdr_len)) {
        } else if (unformat (input, "bp %d", &bp)) {
        } else if (unformat (input, "v4-nh %U",
                             unformat_ip46_address,
                             &brp.frp_addr, 0)) {
        } else if (unformat (input, "mpls %d", &out_label)) {
            vec_add1(brp.frp_label_stack, out_label);
        } else {
            error = unformat_parse_error (input);
            goto done;
        }
    }

    bti.bti_hdr_len = bier_hdr_bit_len_to_id(hdr_len);
    // FIXME
    bti.bti_type    = BIER_TABLE_MPLS_SPF;

    if (add)
    {
        bier_table_route_add(&bti, bp, &brp);
    }
    else
    {
        bier_table_route_remove(&bti, bp, &brp);
    }

done:
    return (error);
}

VLIB_CLI_COMMAND (bier_route_command) = {
  .path = "bier route",
  .short_help = "Add/delete BIER Routes",
  .function = vnet_bier_route_cmd,
};

static clib_error_t *
show_bier_fib_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
    bier_show_flags_t flags;
    index_t bti, bei;
    bier_bp_t bp;

    bp = BIER_BP_INVALID;
    bti = bei = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%d %d", &bti, &bp))
        {
             flags = BIER_SHOW_DETAIL;
        }
        else if (unformat (input, "%d", &bti))
        {
              flags = BIER_SHOW_DETAIL;
        }
        else
        {
            break;
        }
    }

    if (INDEX_INVALID == bti)
    {
        bier_table_show_all(vm, flags);
    }
    else
    {
        if (!pool_is_free_index(bier_table_pool, bti))
        {
            if (BIER_BP_INVALID == bp)
            {
                vlib_cli_output (vm, "%U", format_bier_table, bti, flags);
            }
            else
            {
                vlib_cli_output (vm, "%U", format_bier_table_entry, bti, bp);
            }
        }
    }
    return (NULL);
}

VLIB_CLI_COMMAND (show_bier_fib_command, static) = {
    .path = "show bier fib",
    .short_help = "show bier fib [table-index] [bit-position]",
    .function = show_bier_fib_command_fn,
};
