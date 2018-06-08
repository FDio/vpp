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

#include <igmp/igmp_src.h>
#include <igmp/igmp_group.h>
#include <igmp/igmp.h>

void
igmp_src_free (igmp_src_t * src,
               igmp_group_t * group)
{
  igmp_main_t * im = &igmp_main;
//  IGMP_DBG ("free-src: (%U, %U)",
//            format_igmp_key, src->key,
//            format_igmp_key, group->key);
//  hash_unset_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE],
//                  src->key);
//  hash_unset_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_EXCLUDE],
//                  src->key); clib_mem_free (src->key);
  pool_put (im->srcs, src);
}

igmp_src_t *
igmp_src_alloc (igmp_group_t * group,
                const igmp_key_t * skey,
                igmp_mode_t mode)
{
  igmp_main_t * im = &igmp_main;
  igmp_src_t * src;
//  IGMP_DBG ("new-src: (%U, %U)",
//            format_igmp_key, skey, format_igmp_key, group->key);
  pool_get (im->srcs, src);
  memset (src, 0, sizeof (igmp_src_t));
  src->mode = mode;
  src->key = clib_mem_alloc (sizeof (*skey));
  clib_memcpy (src->key, skey, sizeof (*skey));
  hash_set_mem (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE],
                src->key, src - im->srcs);
  return (src);

  /* if (IGMP_MODE_ROUTER == config->mode) */
  /*       { */
  /*         /\* arm source timer (after expiration remove (S,G)) *\/ */
  /*         igmp_event (im, config, group, src); */
  /*         src->exp_time = vlib_time_now (vm) + IGMP_SRC_TIMER; */
  /*         igmp_create_src_timer (src->exp_time, config->sw_if_index, */
  /*                             group->key, src->key, igmp_src_exp); */
  /*       } */
}
