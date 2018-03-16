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
#include <vnet/devices/devices.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

void
vnet_device_flow_register_cb (u32 hw_if_index, vnet_device_flow_cb_t * fn)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_hw_if_t *hwif;

  vec_validate (dm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (dm->interfaces, hw_if_index);

  ASSERT (hwif->callback == 0);
  hwif->callback = fn;
}

u32
vnet_device_flow_request_range (u32 n_entries)
{
  vnet_device_main_t *dm = &device_main;
  u32 rv = dm->flows_used;
  dm->flows_used += n_entries;
  return rv;
}

void
vnet_device_flow_add (vnet_device_flow_t * flow)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f;
  uword *p;
  u32 flow_index;

  ASSERT (flow->id < dm->flows_used);

  p = hash_get (dm->global_flow_pool_index_by_flow_id, flow->id);
  ASSERT (p == 0);

  pool_get (dm->global_flow_pool, f);
  flow_index = f - dm->global_flow_pool;
  clib_memcpy (f, flow, sizeof (vnet_device_flow_t));
  hash_set (dm->global_flow_pool_index_by_flow_id, flow->id, flow_index);
}

static vnet_device_flow_t *
vnet_device_get_flow (u32 flow_id)
{
  vnet_device_main_t *dm = &device_main;
  uword *p;

  p = hash_get (dm->global_flow_pool_index_by_flow_id, flow_id);
  ASSERT (p != 0);
  return pool_elt_at_index (dm->global_flow_pool, p[0]);
}

void
vnet_device_flow_del (u32 flow_id)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = vnet_device_get_flow (flow_id);
  uword hw_if_index;

  clib_bitmap_foreach(hw_if_index, f->hw_if_bmp,
    ({
     vnet_device_flow_disable (flow_id, hw_if_index);
    }));

  clib_bitmap_free (f->hw_if_bmp);
  memset (f, 0, sizeof (*f));
  pool_put (dm->global_flow_pool, f);
}

void
vnet_device_flow_enable (u32 flow_id, u32 hw_if_index)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = vnet_device_get_flow (flow_id);
  vnet_device_flow_hw_if_t *hwif;
  u32 flow_index, *fidp;

  vec_validate (dm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (dm->interfaces, hw_if_index);

  /* avoid using flow 0 */
  if (pool_elts (hwif->flows) == 0)
    pool_get (hwif->flows, fidp);

  pool_get (hwif->flows, fidp);
  flow_index = fidp - hwif->flows;
  *fidp = flow_id;

  hash_set (hwif->flow_index_by_flow_id, flow_id, flow_index);

  /* don't enable flow twice */
  ASSERT (clib_bitmap_get (f->hw_if_bmp, hw_if_index) == 0);

  f->hw_if_bmp = clib_bitmap_set (f->hw_if_bmp, hw_if_index, 1);

  if (hwif->callback)
    hwif->callback (VNET_DEVICE_FLOW_ADD, f, hw_if_index, flow_index);
}

void
vnet_device_flow_disable (u32 flow_id, u32 hw_if_index)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = vnet_device_get_flow (flow_id);
  vnet_device_flow_hw_if_t *hwif;
  uword *p;

  vec_validate (dm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (dm->interfaces, hw_if_index);

  /* don't disable if not enabled */
  ASSERT (clib_bitmap_get (f->hw_if_bmp, hw_if_index) == 0);

  f->hw_if_bmp = clib_bitmap_set (f->hw_if_bmp, hw_if_index, 0);

  p = hash_get (hwif->flow_index_by_flow_id, flow_id);
  ASSERT (p != 0);

  if (hwif->callback)
    hwif->callback (VNET_DEVICE_FLOW_DEL, f, hw_if_index, p[0]);

  pool_put_index (hwif->flows, p[0]);
  hash_unset (hwif->flow_index_by_flow_id, flow_id);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
