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

#include <vnet/mfib/mfib_itf.h>
#include <vnet/mfib/mfib_signal.h>
#include <vnet/fib/fib_path.h>

mfib_itf_t *mfib_itf_pool;

index_t
mfib_itf_create (fib_node_index_t path_index,
                 mfib_itf_flags_t mfi_flags)
{
    mfib_itf_t *mfib_itf;

    pool_get_aligned(mfib_itf_pool, mfib_itf,
                     CLIB_CACHE_LINE_BYTES);

    mfib_itf->mfi_sw_if_index = fib_path_get_resolving_interface(path_index);
    mfib_itf->mfi_si = INDEX_INVALID;

    /*
     * add the path index to the per-path hash
     */
    mfib_itf->mfi_hash = hash_set(mfib_itf->mfi_hash, path_index, mfi_flags);

    /*
     * the combined flags from all the paths is from just the one contributor
     */
    mfib_itf->mfi_flags = mfi_flags;

    return (mfib_itf - mfib_itf_pool);
}

static mfib_itf_flags_t
mfib_itf_mk_flags (const mfib_itf_t *mfib_itf)
{
    mfib_itf_flags_t combined_flags, flags;
    fib_node_index_t *path_index;

    combined_flags = MFIB_ITF_FLAG_NONE;

    hash_foreach(path_index, flags, mfib_itf->mfi_hash,
    {
        combined_flags |= flags;
    });

    return (combined_flags);
}

int
mfib_itf_update (mfib_itf_t *mfib_itf,
                 fib_node_index_t path_index,
                 mfib_itf_flags_t mfi_flags)
{
    /*
     * add or remove the path index to the per-path hash
     */
    if (MFIB_ITF_FLAG_NONE == mfi_flags)
    {
        hash_unset(mfib_itf->mfi_hash, path_index);
    }
    else
    {
        mfib_itf->mfi_hash = hash_set(mfib_itf->mfi_hash,
                                      path_index,
                                      mfi_flags);
    }

    /*
     * re-generate the combined flags from all the paths.
     */
    mfib_itf->mfi_flags = mfib_itf_mk_flags(mfib_itf);

    /*
     * The interface can be removed if there are no more flags
     */
    return (MFIB_ITF_FLAG_NONE == mfib_itf->mfi_flags);
}

static void
mfib_itf_hash_flush (mfib_itf_t *mfi)
{
    fib_node_index_t path_index, *path_indexp, *all = NULL;
    mfib_itf_flags_t flags;

    hash_foreach(path_index, flags, mfi->mfi_hash,
    {
        vec_add1(all, path_index);
    });

    vec_foreach(path_indexp, all)
    {
        hash_unset(mfi->mfi_hash, *path_indexp);
    };
}

void
mfib_itf_delete (mfib_itf_t *mfi)
{
    mfib_itf_hash_flush(mfi);
    mfib_signal_remove_itf(mfi);
    pool_put(mfib_itf_pool, mfi);
}

u8 *
format_mfib_itf (u8 * s, va_list * args)
{
    mfib_itf_t *mfib_itf;
    vnet_main_t *vnm;
    index_t mfi;

    mfi = va_arg (*args, index_t);

    vnm = vnet_get_main();
    mfib_itf = mfib_itf_get(mfi);

    if (~0 != mfib_itf->mfi_sw_if_index)
    {
        return (format(s, " %U: %U",
                       format_vnet_sw_interface_name,
                       vnm,
                       vnet_get_sw_interface(vnm,
                                             mfib_itf->mfi_sw_if_index),
                       format_mfib_itf_flags, mfib_itf->mfi_flags));
    }
    else
    {
        return (format(s, " local: %U",
                       format_mfib_itf_flags, mfib_itf->mfi_flags));
    }
    return (s);
}

static clib_error_t *
show_mfib_itf_command (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
    index_t mfii;

    if (unformat (input, "%d", &mfii))
    {
        /*
         * show one in detail
         */
        if (!pool_is_free_index(mfib_itf_pool, mfii))
        {
            vlib_cli_output (vm, "%d@%U",
                             mfii,
                             format_mfib_itf, mfii);
        }
        else
        {
            vlib_cli_output (vm, "itf %d invalid", mfii);
        }
    }
    else
    {
        /*
         * show all
         */
        vlib_cli_output (vm, "mFIB interfaces::");
        pool_foreach_index(mfii, mfib_itf_pool,
        ({
            vlib_cli_output (vm, "%d@%U",
                             mfii,
                             format_mfib_itf, mfii);
        }));
    }

    return (NULL);
}

/*?
 * This commnad displays an MFIB interface, or all interfaces, indexed by their unique
 * numerical indentifier.
 ?*/
VLIB_CLI_COMMAND (show_mfib_itf, static) = {
  .path = "show mfib interface",
  .function = show_mfib_itf_command,
  .short_help = "show mfib interface",
};
