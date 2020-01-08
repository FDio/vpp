/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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


#include <vnet/match/match_engine.h>
#include <vnet/match/match_set_dp.h>

#include <vnet/match/engines/linear/match_linear_dp.h>

match_engine_linear_t *match_engine_linear_pool;

static match_set_app_t
match_linear_apply (match_set_t * ms,
		    vnet_link_t linkt, match_set_tag_flags_t flags)
{
  match_engine_linear_t *mel;

  pool_get (match_engine_linear_pool, mel);

  mel->mel_set = match_set_get_index (ms);
  mel->mel_offset = match_set_get_l2_offset (linkt, flags);
  mel->mel_linkt = linkt;

  return (mel - match_engine_linear_pool);
}


static void
match_linear_unapply (match_set_t * ms, match_set_app_t mb)
{
  pool_put_index (match_engine_linear_pool, mb);
}

static void
match_linear_update (match_set_t * ms,
		     match_set_app_t msa,
		     vnet_link_t linkt, match_set_tag_flags_t flags)
{
}

static u8 *
format_match_linear (u8 * s, va_list * args)
{

  return (s);
}

static clib_error_t *
match_linear_init (vlib_main_t * vm)
{
  /*
   * The linear matcher can do all match types and semantics
   */
#define _(a,b)                                                          \
  const static match_engine_vft_t ml_vft_##a = {                        \
    .mev_apply = match_linear_apply,                                    \
    .mev_update = match_linear_update,                                  \
    .mev_unapply = match_linear_unapply,                                \
    .mev_format = format_match_linear,                                  \
    .mev_match = match_engine_linear_match_##a,                         \
    .mev_match_one = match_engine_linear_match_one_##a,                 \
  };                                                                    \
                                                                        \
  match_engine_register ("linear", MATCH_TYPE_##a,                      \
                         MATCH_SEMANTIC_ANY, 100, &ml_vft_##a);         \
  match_engine_register ("linear", MATCH_TYPE_##a,                      \
                         MATCH_SEMANTIC_FIRST, 100, &ml_vft_##a);
  foreach_match_type
#undef _
    return (NULL);
}

VLIB_INIT_FUNCTION (match_linear_init) =
{
.runs_after = VLIB_INITS ("match_init"),};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
