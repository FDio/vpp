/*---------------------------------------------------------------------------
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */

#ifndef __included_vppjni_bridge_domain_h__
#define __included_vppjni_bridge_domain_h__

#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vppinfra/mhash.h>

/*
 * The L2fib key is the mac address and bridge domain ID
 */
#define MAC_ADDRESS_SIZE  6

typedef struct {
  union {
    struct {
      u16 unused1;
      u8  mac[MAC_ADDRESS_SIZE]; 
    } fields;
    u64 raw;
  };
} l2fib_u64_mac_t;

/* 
 * The l2fib entry results
 */
typedef struct {
  u32 bd_id;
  l2fib_u64_mac_t mac_addr;
  u32 sw_if_index;
  u8  learned:1;
  u8  bvi:1;
  u8  filter:1;      // drop packets to/from this mac
  u8  unused1:5;
} bd_l2fib_oper_t;

typedef struct {
  u32 bd_id;
  u8 * bd_name;
} bd_local_cfg_t;

typedef struct {
  u32 bd_id;
  u32 sw_if_index;
  u32 shg;
} bd_sw_if_oper_t;

typedef struct {
  u32 bd_id;
  u8 flood:1;
  u8 forward:1;
  u8 learn:1;
  u8 uu_flood:1;
  u8 arp_term:1;
  u8 unused1:3;
  u32 bvi_sw_if_index;
  u32 n_sw_ifs;
  bd_sw_if_oper_t * bd_sw_if_oper;
  f64 last_sync_time;
  mhash_t l2fib_index_by_mac;
  bd_l2fib_oper_t * l2fib_oper;	// vector indexed by l2fib_index
} vjbd_oper_t;

#define BD_OPER_REFRESH_INTERVAL  	2.0
#define BD_OPER_L2FIB_REFRESH_INTERVAL	5.0

typedef struct {
  u32 next_bd_id;
  uword * bd_index_bitmap;
  uword * bd_index_by_id;
  mhash_t bd_id_by_name;
  bd_local_cfg_t * local_cfg;		// vector indexed by bd_index
  vjbd_oper_t * bd_oper;		// vector indexed by oper_bd_index
  f64 bd_oper_last_sync_all_time;
  bd_sw_if_oper_t * sw_if_oper;	// vector indexed by sw_if_index
  f64 l2fib_oper_last_sync_time;
  uword * bd_id_by_sw_if_index;
  uword * oper_bd_index_by_bd_id;
} vjbd_main_t;

extern vjbd_main_t vjbd_main;

always_inline
u64 l2fib_mac_to_u64 (u8 * mac_address) {
  u64 temp;

  // The mac address in memory is A:B:C:D:E:F
  // The bd id in register is H:L
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  // Create the in-register key as F:E:D:C:B:A:H:L
  // In memory the key is L:H:A:B:C:D:E:F
  temp = *((u64 *)(mac_address - 2));
  temp = (temp & ~0xffff);
#else
  // Create the in-register key as H:L:A:B:C:D:E:F
  // In memory the key is H:L:A:B:C:D:E:F
  temp = *((u64 *)(mac_address)) >> 16;
#endif

  return temp;
}

static_always_inline void vjbd_main_init (vjbd_main_t *bdm)
{
  bdm->bd_index_by_id = hash_create (0, sizeof(uword));
  mhash_init_vec_string (&bdm->bd_id_by_name, sizeof (u32));
  bdm->bd_id_by_sw_if_index = hash_create (0, sizeof (u32));
  bdm->oper_bd_index_by_bd_id = hash_create (0, sizeof (u32));
}

static_always_inline u32 vjbd_id_is_valid (vjbd_main_t * bdm, u32 bd_id)
{
  return ((bd_id != 0) && (bd_id != ~0) && (bd_id <= bdm->next_bd_id));
}

static_always_inline u32 vjbd_index_is_free (vjbd_main_t * bdm, u16 bd_index)
{
  u32 bd_id = vec_elt_at_index(bdm->local_cfg, bd_index)->bd_id;

  return (!clib_bitmap_get (bdm->bd_index_bitmap, (bd_index)) &&
          (bd_index < vec_len (bdm->local_cfg)) &&
          ((bd_id == 0) || (bd_id == ~0)));
}

static_always_inline u32 vjbd_index_is_valid (vjbd_main_t * bdm, u16 bd_index)
{
  return (clib_bitmap_get (bdm->bd_index_bitmap, bd_index) &&
          (bd_index < vec_len (bdm->local_cfg)));
}

static_always_inline u32 vjbd_id_from_name (vjbd_main_t * bdm,
                                            const u8 * bd_name)
{
  u32 bd_id;
  uword * p;

  ASSERT (vec_c_string_is_terminated (bd_name));

  if (bdm->next_bd_id == 0)
    return ~0;

  p = mhash_get (&bdm->bd_id_by_name, (void *)bd_name);
  if (p)
    {
      bd_id = p[0];
      ASSERT (vjbd_id_is_valid (bdm, bd_id));
    }
  else
    bd_id = ~0;

  return bd_id;
}

static_always_inline u32 vjbd_index_from_id (vjbd_main_t * bdm, u32 bd_id)
{
  uword * p;
  u16 bd_index;

  ASSERT (vjbd_id_is_valid (bdm, bd_id));

  p = hash_get (bdm->bd_index_by_id, bd_id);

  ASSERT (p); // there is always an index associated with a valid bd_id
  bd_index = p[0];

  ASSERT (vjbd_index_is_valid (bdm, bd_index));

  return bd_index;
}

static_always_inline u32 vjbd_id_from_index (vjbd_main_t * bdm, u16 bd_index)
{
  u32 bd_id;

  ASSERT (vjbd_index_is_valid (bdm, bd_index));

  bd_id = vec_elt_at_index(bdm->local_cfg, bd_index)->bd_id;

  ASSERT (vjbd_id_is_valid (bdm, bd_id));

  return bd_id;
}

static_always_inline u8 * vjbd_name_from_id (vjbd_main_t * bdm, u32 bd_id)
{
  u16 bd_index = vjbd_index_from_id (bdm, bd_id);

  return vec_elt_at_index(bdm->local_cfg, bd_index)->bd_name;
}

static_always_inline u8 * vjbd_oper_name_from_id (vjbd_main_t * bdm, u32 bd_id)
{
    if (vjbd_id_is_valid (bdm, bd_id)) {
        return format(0, "%s", vjbd_name_from_id(bdm, bd_id));
    } else {
        return format(0, "BridgeDomainOper%d", bd_id);
    }
}

static_always_inline vjbd_oper_t * vjbd_oper_from_id (vjbd_main_t * bdm,
                                                  u32 bd_id)
{
  u16 bd_index = vjbd_index_from_id (bdm, bd_id);
  return vec_elt_at_index (bdm->bd_oper, bd_index);
}

static_always_inline void vjbd_oper_maybe_sync_from_vpp (vjbd_main_t * bdm, 
                                                       u32 bd_id)
{
#ifdef VPPJNI_OPER
  vppjni_vpe_api_msg_main_t *ovam = ovam_get_main ();

  if (bd_id == ~0)
    {
      if ((ovam_time_now (ovam) - bdm->bd_oper_last_sync_all_time) >
          BD_OPER_REFRESH_INTERVAL)
        {
          ovam_bridge_domain_dump (bd_id);
          bdm->bd_oper_last_sync_all_time = ovam_time_now (ovam);
        }
    }
    
  else 
    {
      vjbd_oper_t * bd_oper = vjbd_oper_from_id (bdm, bd_id);

      if ((ovam_time_now (ovam) - bd_oper->last_sync_time) >
          BD_OPER_REFRESH_INTERVAL)
        {
          ovam_bridge_domain_dump (bd_id);

          bd_oper->last_sync_time = ovam_time_now (ovam);
        }
    }
#endif
}

static_always_inline u32 vjbd_id_from_sw_if_index (vjbd_main_t * bdm,
                                                 u32 sw_if_index)
{
  bd_sw_if_oper_t * bd_sw_if_oper;
  u32 bd_id = ~0;

  vjbd_oper_maybe_sync_from_vpp (bdm, ~0);
  if (sw_if_index < vec_len (bdm->sw_if_oper))
    {
      bd_sw_if_oper = vec_elt_at_index (bdm->sw_if_oper, sw_if_index);
      bd_id = bd_sw_if_oper->bd_id;
    }

  return bd_id;
}

static_always_inline u8 * vjbd_name_from_sw_if_index (vjbd_main_t * bdm,
                                                    u32 sw_if_index)
{
  u32 bd_id, bd_index;
  u8 * bd_name = 0;
  
  /* DAW-FIXME:
  ASSERT (ovam_sw_if_index_valid (ovam_get_main(), sw_if_index));
  */
  vjbd_oper_maybe_sync_from_vpp (bdm, ~0);
  bd_id = vjbd_id_from_sw_if_index (bdm, sw_if_index);
  if (vjbd_id_is_valid (bdm, bd_id))
    {
      bd_index = vjbd_index_from_id (bdm, bd_id);
      bd_name = vec_elt_at_index (bdm->local_cfg, bd_index)->bd_name;
    }

  return bd_name;
}

static_always_inline u32 
vjbd_oper_l2fib_index_from_mac (vjbd_oper_t * bd_oper, u8 * mac)
{
  u32 l2fib_index;
  uword * p;

  p = mhash_get (&bd_oper->l2fib_index_by_mac, mac);
  if (p)
    {
      l2fib_index = p[0];
      ASSERT (l2fib_index < vec_len (bd_oper->l2fib_oper));
    }
  else
    l2fib_index = ~0;

  return l2fib_index;
}

static_always_inline u32 vjbd_local_cfg_next_id (vjbd_main_t * bdm, 
                                               u32 bd_id)
{
  u32 i, end = vec_len (bdm->local_cfg);
  u32 next_bd_id = 0;

  if ((bd_id == 0) || vjbd_id_is_valid (bdm, bd_id))
    for (i = 0; i < end; i++)
      {
        u32 curr_bd_id = bdm->local_cfg[i].bd_id;
        if ((curr_bd_id != ~0) && (curr_bd_id > bd_id) && 
            ((next_bd_id == 0) || (curr_bd_id < next_bd_id)))
          next_bd_id = curr_bd_id;
      }

  return next_bd_id;
}

static_always_inline u32 vjbd_sw_if_oper_next_index (vjbd_main_t * bdm, 
                                                   u32 start, u32 bd_id)
{
  u32 i, end = vec_len (bdm->sw_if_oper);

  if (vjbd_id_is_valid (bdm, bd_id))
    for (i = start; i < end; i++)
      if (bdm->sw_if_oper[i].bd_id == bd_id)
        return i;

  return ~0;
}

static_always_inline void 
vjbd_oper_l2fib_maybe_sync_from_vpp (vjbd_main_t * bdm)
{
#ifdef VPPJNI_OPER
  vppjni_vpe_api_msg_main_t *ovam = ovam_get_main ();
  if ((ovam_time_now (ovam) - bdm->l2fib_oper_last_sync_time) >
      BD_OPER_L2FIB_REFRESH_INTERVAL)
    {
      ovam_l2fib_table_dump ();
      bdm->l2fib_oper_last_sync_time = ovam_time_now (ovam);
    }
#endif
}

static_always_inline void vjbd_l2fib_oper_reset (vjbd_main_t * bdm)
{
  vjbd_oper_t * bd_oper;

  vec_foreach (bd_oper, bdm->bd_oper)
    {
      mhash_init (&bd_oper->l2fib_index_by_mac, sizeof (u32), MAC_ADDRESS_SIZE);
      vec_reset_length (bd_oper->l2fib_oper);      
    }
}

static_always_inline void vjbd_oper_reset (vjbd_main_t * bdm, u32 bd_id)
{
  u16 bd_index;
  u32 si, len;
  vjbd_oper_t * bd_oper;
  u32 end;

  if (!bdm->bd_oper)
    {
      ASSERT (vec_len (bdm->sw_if_oper) == 0);
      return;
    }

  if (bd_id == ~0)
    {
      bdm->bd_oper_last_sync_all_time = 0.0;
      bd_index = 0;
      end = vec_len (bdm->bd_oper);
    }
  else
    {
      bd_index = vjbd_index_from_id (bdm, bd_id);
      end = bd_index + 1;
    }

  for (; bd_index < end; bd_index++)
    {
      bd_oper = vec_elt_at_index (bdm->bd_oper, bd_index);
      bd_oper->last_sync_time = 0.0;

      len = vec_len (bdm->sw_if_oper);
      for (si = vjbd_sw_if_oper_next_index (bdm, 0, bd_id);
           (si != ~0) && (si < len);
           si = vjbd_sw_if_oper_next_index (bdm, si + 1, bd_id))
        {
          bd_sw_if_oper_t * bd_sw_if_oper;

          bd_sw_if_oper = vec_elt_at_index (bdm->sw_if_oper, si);
          bd_sw_if_oper->bd_id = ~0;
        }
    }
}

static_always_inline void 
vjbd_sw_if_add_del (u32 sw_if_index ,u32 bd_id, u8 bvi, u8 shg, u8 is_add)
{
  vjbd_main_t * bdm = &vjbd_main;
  u16 bd_index = vjbd_index_from_id (bdm, bd_id);
  vjbd_oper_t * bd_oper = vec_elt_at_index (bdm->bd_oper, bd_index);
  bd_sw_if_oper_t * bd_sw_if_oper;
  
  ASSERT (vjbd_id_is_valid (bdm, bd_id));
  /* DAW-FIXME
  ASSERT (ovam_sw_if_index_valid (ovam_get_main (), sw_if_index));
  */

  vec_validate (bdm->sw_if_oper, sw_if_index);
  bd_sw_if_oper = vec_elt_at_index (bdm->sw_if_oper, sw_if_index);
  if (is_add)
    {
      bd_sw_if_oper->bd_id = bd_id;
      bd_sw_if_oper->shg = shg;
      bd_oper->bvi_sw_if_index = bvi ? sw_if_index : ~0;
    }
  else
    {
      bd_sw_if_oper->bd_id = 0;
      bd_sw_if_oper->shg = 0;
      if (bd_oper->bvi_sw_if_index == sw_if_index)
        bd_oper->bvi_sw_if_index = ~0;
    }
}

static_always_inline u32 vjbd_id_sw_if_count (vjbd_main_t * bdm, u32 bd_id)
{
  u32 count = 0, i, end = vec_len (bdm->sw_if_oper);

  if (vjbd_id_is_valid (bdm, bd_id))
    for (count = i = 0; i < end; i++)
      if (bdm->sw_if_oper[i].bd_id == bd_id)
        count++;

  return count;
}

static_always_inline u32 vjbd_find_or_add_bd (vjbd_main_t * bdm, u8 * bd_name)
{
  u16 bd_index;
  u32 bd_id;
  bd_local_cfg_t * bd_local_cfg;
  uword mhash_val_bd_id;

  bd_id = vjbd_id_from_name (bdm, bd_name);
  if (bd_id != ~0)
    return bd_id;

  mhash_val_bd_id = bd_id = ++bdm->next_bd_id;
  mhash_set_mem (&bdm->bd_id_by_name, (void *)bd_name, &mhash_val_bd_id, 0);

  bd_index = clib_bitmap_first_clear (bdm->bd_index_bitmap);
  vec_validate (bdm->local_cfg, bd_index);
  vec_validate (bdm->bd_oper, bd_index);

  ASSERT (vjbd_index_is_free (bdm, bd_index));

  bd_local_cfg = vec_elt_at_index (bdm->local_cfg, bd_index);
  bd_local_cfg->bd_id = bd_id;
  vec_validate_init_c_string (bd_local_cfg->bd_name, bd_name,
                              vec_len (bd_name) - 1);
  hash_set (bdm->bd_index_by_id, bd_id, bd_index);
  bdm->bd_index_bitmap = clib_bitmap_set (bdm->bd_index_bitmap,
                                          bd_index, 1);
  return bd_id;
}

static_always_inline void vjbd_delete_bd (vjbd_main_t * bdm, u32 bd_id)
{
  u16 bd_index;
  bd_local_cfg_t * bd_local_cfg;

  ASSERT (vjbd_id_is_valid (bdm, bd_id));

  // bd must not have any members before deleting
  ASSERT (!vjbd_id_sw_if_count (bdm, bd_id));

  bd_index = vjbd_index_from_id (bdm, bd_id);
  bd_local_cfg = vec_elt_at_index (bdm->local_cfg, bd_index);
  vjbd_oper_reset (bdm, bd_id);

  mhash_unset (&bdm->bd_id_by_name, vjbd_name_from_id (bdm, bd_id), 0);
  bdm->bd_index_bitmap = clib_bitmap_set (bdm->bd_index_bitmap,
                                          bd_index, 0);
  hash_unset (bdm->bd_index_by_id, bd_id);
  bd_local_cfg->bd_id = ~0;
  vec_validate_init_c_string (bd_local_cfg->bd_name, "", 0);

  if (clib_bitmap_is_zero (bdm->bd_index_bitmap))
    {
      vec_reset_length (bdm->local_cfg);
      vec_reset_length (bdm->bd_oper);
    }

  /* Force a resync of all bd_oper data. */
  bdm->bd_oper_last_sync_all_time = 0.0;
  vjbd_oper_maybe_sync_from_vpp (bdm, ~0);
}

#endif /* __included_vppjni_vpp_bridge_domain_h__ */
