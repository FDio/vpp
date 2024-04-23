/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>

typedef struct tm_node_params_
{
  /* 0xFFFFFFFF is invalid and rest others are valid values */
  u32 shaper_id;
  union
  {
    struct
    {
      /* The ingress queue buffer length */
      u32 ingress_q_len;
      u32 threshold_profile_id;
      u32 wred_profile_id;
    } leaf;

    struct
    {
      u32 num_sp_priorities;
      /* is scheduling done with pkt mode(1) or byte mode(0). defined per sp
       * priority */
      u8 *sched_pkt_mode;
    } nonleaf;
  };
  u8 is_leaf;
} tm_node_params_t;

typedef struct tm_node_connect_params_
{
  u32 port_id;
  u32 node_id;
  u32 parent_node_id;
  u32 prio;
  u32 weight;
} tm_node_connect_params_t;

typedef struct tm_shaper_params_
{
  struct
  {
    u64 rate;
    u64 burst_size;
  } commit;

  struct
  {
    u64 rate;
    u64 burst_size;
  } peak;

  i32 pkt_len_adj;
  u8 pkt_mode;
} tm_shaper_params_t;

typedef enum
{
  TM_BYTE_BASED_WEIGHTS,
  TM_FRAME_BASED_WEIGHTS
} tm_sched_mode_t;

typedef struct tm_sched_params_
{
  tm_sched_mode_t sched_modes;
  u32 sched_weight;
  u64 sched_prof;
} tm_sched_params_t;

typedef struct tm_system_t_
{
  u32 hw_if_idx;
  int (*node_create) (u32 hw_if_idx, tm_node_params_t *args);
  int (*node_delete) (u32 hw_if_idx, u32 node_idx);
  int (*node_connect) (u32 hw_if_idx, tm_node_connect_params_t *param);
  int (*node_disconnect) (u32 hw_if_idx, u32 node_idx);
  int (*shaper_create) (u32 hw_if_idx, tm_shaper_params_t *param);
  int (*shaper_delete) (u32 hw_if_idx, u32 shaper_id);
  int (*sched_create) (u32 hw_if_idx, tm_sched_params_t *param);
  int (*sched_delete) (u32 hw_if_idx, u32 sched_id);
} tm_system_t;

int tm_sys_node_create (u32 hw_if_idx, tm_node_params_t *args);
int tm_sys_node_delete (u32 hw_if_idx, u32 node_idx);
int tm_sys_node_connect (u32 hw_if_idx, tm_node_connect_params_t *param);
int tm_sys_node_disconnect (u32 hw_if_idx, u32 node_idx);
int tm_sys_sched_create (u32 hw_if_idx, tm_sched_params_t *param);
int tm_sys_sched_delete (u32 hw_if_idx, u32 sched_id);
int tm_sys_shaper_create (u32 hw_if_idx, tm_shaper_params_t *param);
int tm_sys_shaper_delete (u32 hw_if_idx, u32 shaper_id);
int pktio_dev_tm_system_register (tm_system_t *tm_sys, u32 hw_if_idx);
