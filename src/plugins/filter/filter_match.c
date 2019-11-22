/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <filter/filter_match.h>

static filter_match_vft_t *fm_vfts;

u8 *
format_filter_match_dir (u8 * s, va_list * args)
{
  filter_match_dir_t fd = va_arg (*args, filter_match_dir_t);

  switch (fd)
    {
#define _(u,v) case FILTER_MATCH_##u:            \
        return (format (s, "%s", v));
      foreach_filter_match_dir
#undef _
    }

  return (format (s, "unknown"));
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword
unformat_filter_match_dir (unformat_input_t * input, va_list * args)
{
  filter_match_dir_t *fd = va_arg (*args, filter_match_dir_t *);

  if (0)
    ;
#define _(u,v) else if (unformat (input, v)) { \
      *fd = FILTER_MATCH_##u;                  \
      return (1);                              \
  }
  foreach_filter_match_dir
#undef _
    return 0;
}

u8 *
format_filter_match_res (u8 * s, va_list * args)
{
  filter_match_res_t fd = va_arg (*args, filter_match_res_t);

  switch (fd)
    {
#define _(u,v) case FILTER_MATCH_##u:            \
        return (format (s, "%s", v));
      foreach_filter_match_res
#undef _
    }

  return (format (s, "unknown"));
}

u8 *
format_filter_match (u8 * s, va_list * args)
{
  /* filter_match_t *fm; */
  /* int indent; */

  /* fm = va_arg (*args, filter_match_t *); */
  /* indent = va_arg (*args, int); */

  /* s = format (s, "\n%Urule:%d", */
  /*             format_white_space, indent, fm->fm_rule); */
  /* s = format (s, "\n%U%U:%U", */
  /*             format_white_space, indent, */
  /*             format_filter_match_res, FILTER_MATCH_YES, */
  /*             format_dpo_id, &fm->fm_results[FILTER_MATCH_YES], indent + 2); */
  /* s = format (s, "\n%U%U:%U", */
  /*             format_white_space, indent, */
  /*             format_filter_match_res, FILTER_MATCH_NO, */
  /*             format_dpo_id, &fm->fm_results[FILTER_MATCH_NO], indent + 2); */

  return (s);
}

void
filter_match_stack (dpo_id_t * match,
		    index_t rule, const dpo_id_t * pos, const dpo_id_t * neg)
{
  filter_match_t *fm;

  fm = fm_vfts[match->dpoi_type].fmv_get_base (match);

  fm->fm_rule = rule;

  /* the positive match result */
  dpo_stack (fm->fm_base.dpoi_type,
	     fm->fm_base.dpoi_proto, &fm->fm_results[FILTER_MATCH_YES], pos);
  /* the negative match result */
  dpo_stack (fm->fm_base.dpoi_type,
	     fm->fm_base.dpoi_proto, &fm->fm_results[FILTER_MATCH_NO], neg);
}

void
filter_match_unstack (dpo_id_t * match)
{
  filter_match_t *fm;

  fm = fm_vfts[match->dpoi_type].fmv_get_base (match);

  fm->fm_rule = INDEX_INVALID;

  dpo_reset (&fm->fm_results[FILTER_MATCH_YES]);
  dpo_reset (&fm->fm_results[FILTER_MATCH_NO]);
}

uword
unformat_filter_match (unformat_input_t * input, va_list * args)
{
  filter_match_vft_t *vft;
  dpo_proto_t dproto;
  dpo_id_t *dpo;

  dpo = va_arg (*args, dpo_id_t *);
  dproto = va_arg (args, int);

  vec_foreach (vft, fm_vfts)
  {
    if (vft->fmv_unformat)
      if (unformat (input, "%U", vft->fmv_unformat, dpo, dproto))
	return (1);
  }

  return (0);
}

void
filter_match_register (dpo_type_t type, const filter_match_vft_t * vft)
{
  vec_validate (fm_vfts, type);

  fm_vfts[type] = *vft;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
