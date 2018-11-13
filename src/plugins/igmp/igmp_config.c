/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <igmp/igmp_config.h>
#include <igmp/igmp.h>

void
igmp_clear_config (igmp_config_t * config)
{
  igmp_group_t *group;
  u32 ii;

  IGMP_DBG ("clear-config: %U",
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index);

  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      igmp_group_clear (group);
    }));
  /* *INDENT-ON* */

  for (ii = 0; ii < IGMP_CONFIG_N_TIMERS; ii++)
    {
      igmp_timer_retire (&config->timers[ii]);
    }
}

igmp_config_t *
igmp_config_lookup (u32 sw_if_index)
{
  igmp_main_t *im;

  im = &igmp_main;

  if (vec_len (im->igmp_config_by_sw_if_index) > sw_if_index)
    {
      u32 index;

      index = im->igmp_config_by_sw_if_index[sw_if_index];

      if (~0 != index)
	return (vec_elt_at_index (im->configs, index));
    }
  return NULL;
}

u32
igmp_config_index (const igmp_config_t * c)
{
  return (c - igmp_main.configs);
}

igmp_config_t *
igmp_config_get (u32 index)
{
  return (pool_elt_at_index (igmp_main.configs, index));
}

igmp_group_t *
igmp_group_lookup (igmp_config_t * config, const igmp_key_t * key)
{
  uword *p;
  igmp_group_t *group = NULL;
  if (!config)
    return NULL;

  p = hash_get_mem (config->igmp_group_by_key, key);
  if (p)
    group = pool_elt_at_index (igmp_main.groups, p[0]);

  return group;
}

u8 *
format_igmp_config_timer_type (u8 * s, va_list * args)
{
  igmp_config_timer_type_t type = va_arg (*args, igmp_config_timer_type_t);

  switch (type)
    {
#define _(v,t) case IGMP_CONFIG_TIMER_##v: return (format (s, "%s", t));
      foreach_igmp_config_timer_type
#undef _
    }
  return (s);
}


u8 *
format_igmp_config (u8 * s, va_list * args)
{
  igmp_config_t *config;
  igmp_group_t *group;
  vnet_main_t *vnm;
  u32 ii;

  config = va_arg (*args, igmp_config_t *);
  vnm = vnet_get_main ();

  s = format (s, "interface: %U mode: %U %U",
	      format_vnet_sw_if_index_name, vnm, config->sw_if_index,
	      format_igmp_mode, config->mode,
	      format_igmp_proxy_device_id, config->proxy_device_id);

  for (ii = 0; ii < IGMP_CONFIG_N_TIMERS; ii++)
    {
      s = format (s, "\n  %U:%U",
		  format_igmp_config_timer_type, ii,
		  format_igmp_timer_id, config->timers[ii]);
    }

  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      s = format (s, "\n%U", format_igmp_group, group, 4);
    }));
  /* *INDENT-ON* */

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
