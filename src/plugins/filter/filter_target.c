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

#include <filter/filter_target.h>

static filter_target_vft_t *ft_vfts;

uword
unformat_filter_target (unformat_input_t * input, va_list * args)
{
  filter_target_vft_t *vft;
  dpo_proto_t dproto;
  dpo_id_t *dpo;

  dpo = va_arg (*args, dpo_id_t *);
  dproto = va_arg (args, int);

  vec_foreach (vft, ft_vfts)
  {
    if (vft->ftv_unformat)
      if (unformat (input, "%U", vft->ftv_unformat, dpo, dproto))
	return (1);
  }

  return (0);
}

void
filter_target_rule_update (const dpo_id_t * dpo, index_t fri)
{
  if (ft_vfts[dpo->dpoi_type].ftv_rule_update)
    ft_vfts[dpo->dpoi_type].ftv_rule_update (dpo, fri);
}

void
filter_target_register (dpo_type_t type, const filter_target_vft_t * vft)
{
  vec_validate (ft_vfts, type);

  ft_vfts[type] = *vft;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
