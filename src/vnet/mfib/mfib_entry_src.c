/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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


#include <vnet/mfib/mfib_entry_src.h>

static mfib_entry_src_vft mfib_entry_src_vfts[MFIB_N_SOURCES];

static void
mfib_entry_src_default_deactiviate (mfib_entry_t *mfib_entry,
                                    mfib_entry_src_t *msrc)
{
}

static void
mfib_entry_src_default_activiate (mfib_entry_t *mfib_entry,
                                  mfib_entry_src_t *msrc)
{
}

static mfib_src_res_t
mfib_entry_src_default_cover_change (mfib_entry_t *mfib_entry,
                                     mfib_entry_src_t *msrc)
{
    return (MFIB_SRC_OK);
}

static mfib_src_res_t
mfib_entry_src_default_cover_update (mfib_entry_t *mfib_entry,
                                     mfib_entry_src_t *msrc)
{
    return (MFIB_SRC_OK);
}

void
mfib_entry_src_register (mfib_source_t source,
                         const mfib_entry_src_vft *mvft)
{
    mfib_entry_src_vfts[source] = *mvft;
}

void
mfib_entry_src_deactivate (mfib_entry_t *mfib_entry,
                           mfib_entry_src_t *msrc)
{
    if (NULL != msrc)
        mfib_entry_src_vfts[msrc->mfes_src].mev_deactivate(mfib_entry, msrc);
}

void
mfib_entry_src_activate (mfib_entry_t *mfib_entry,
                         mfib_entry_src_t *msrc)
{
    if (NULL != msrc)
        mfib_entry_src_vfts[msrc->mfes_src].mev_activate(mfib_entry, msrc);
}

mfib_src_res_t
mfib_entry_src_cover_change (mfib_entry_t *mfib_entry,
                             mfib_entry_src_t *msrc)
{
    return (mfib_entry_src_vfts[msrc->mfes_src].mev_cover_change(mfib_entry, msrc));
}

mfib_src_res_t
mfib_entry_src_cover_update (mfib_entry_t *mfib_entry,
                             mfib_entry_src_t *msrc)
{
    return (mfib_entry_src_vfts[msrc->mfes_src].mev_cover_update(mfib_entry, msrc));
}

void
mfib_entry_src_module_init (void)
{
    mfib_entry_src_vft mvft = {
        .mev_activate = mfib_entry_src_default_activiate,
        .mev_deactivate = mfib_entry_src_default_deactiviate,
        .mev_cover_change = mfib_entry_src_default_cover_change,
        .mev_cover_update = mfib_entry_src_default_cover_update,
    };
    mfib_source_t source;

    FOREACH_MFIB_SOURCE(source)
    {
        mfib_entry_src_register(source, &mvft);
    }

    mfib_entry_src_rr_module_init();
}
