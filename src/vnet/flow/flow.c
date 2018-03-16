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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

int
vnet_flow_register_interface_cb (u32 hw_if_index,
				 vnet_flow_interface_cb_t * fn,
				 format_function_t * fmt_fn)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_hw_if_t *hwif;

  vec_validate (fm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (fm->interfaces, hw_if_index);

  if (hwif->callback != 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hwif->callback = fn;
  hwif->format_interface_flow = fmt_fn;
  return 0;
}

int
vnet_flow_get_range (char *owner, u32 count, u32 * start)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *r;

  /* skip 0 */
  if (fm->flows_used == 0)
    fm->flows_used = 1;

  *start = fm->flows_used;
  fm->flows_used += count;
  vec_add2 (fm->ranges, r, 1);
  r->start = *start;
  r->count = count;
  r->owner = format (0, "%s%c", owner, 0);
  return 0;
}

int
vnet_flow_add (vnet_flow_t * flow)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f;
  uword *p;
  u32 flow_index;

  ASSERT (flow->id < fm->flows_used);

  p = hash_get (fm->global_flow_pool_index_by_flow_id, flow->id);
  ASSERT (p == 0);

  pool_get (fm->global_flow_pool, f);
  flow_index = f - fm->global_flow_pool;
  clib_memcpy (f, flow, sizeof (vnet_flow_t));
  f->hw_if_bmp = 0;
  hash_set (fm->global_flow_pool_index_by_flow_id, flow->id, flow_index);
  return 0;
}

vnet_flow_t *
vnet_get_flow (u32 flow_id)
{
  vnet_flow_main_t *fm = &flow_main;
  uword *p;

  p = hash_get (fm->global_flow_pool_index_by_flow_id, flow_id);
  if (p)
    return pool_elt_at_index (fm->global_flow_pool, p[0]);
  return 0;
}

int
vnet_flow_del (u32 flow_id)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f = vnet_get_flow (flow_id);
  uword hw_if_index;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  /* *INDENT-OFF* */
  clib_bitmap_foreach(hw_if_index, f->hw_if_bmp,
    ({
     vnet_flow_disable (flow_id, hw_if_index);
    }));
  /* *INDENT-ON* */

  clib_bitmap_free (f->hw_if_bmp);
  memset (f, 0, sizeof (*f));
  pool_put (fm->global_flow_pool, f);
  return 0;
}

int
vnet_flow_enable (u32 flow_id, u32 hw_if_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f = vnet_get_flow (flow_id);
  vnet_flow_hw_if_t *hwif;

  /* don't enable flow twice */
  if (clib_bitmap_get (f->hw_if_bmp, hw_if_index))
    return VNET_FLOW_ERROR_ALREADY_DONE;

  vec_validate (fm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (fm->interfaces, hw_if_index);

  if (hwif->callback == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  f->hw_if_bmp = clib_bitmap_set (f->hw_if_bmp, hw_if_index, 1);

  return hwif->callback (VNET_FLOW_INTERFACE_ADD_FLOW, hw_if_index, f);
}

int
vnet_flow_disable (u32 flow_id, u32 hw_if_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f = vnet_get_flow (flow_id);
  vnet_flow_hw_if_t *hwif;

  /* don't disable if not enabled */
  if (clib_bitmap_get (f->hw_if_bmp, hw_if_index) == 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  vec_validate (fm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (fm->interfaces, hw_if_index);

  if (hwif->callback == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  f->hw_if_bmp = clib_bitmap_set (f->hw_if_bmp, hw_if_index, 0);

  return hwif->callback (VNET_FLOW_INTERFACE_DEL_FLOW, hw_if_index, f);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
