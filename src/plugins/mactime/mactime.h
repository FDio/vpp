
/*
 * mactime.h - time-based src mac address filtration
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_mactime_h__
#define __included_mactime_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp.h>
#include <vlib/counter.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/time_range.h>
#include <vppinfra/bihash_8_8.h>

#define MACTIME_RANGE_TYPE_DROP 0
#define MACTIME_RANGE_TYPE_ALLOW 1

typedef struct
{
  u8 *device_name;
  u8 mac_address[6];
  u32 flags;
  clib_timebase_range_t *ranges;
} mactime_device_t;

/** Always drop packets from this device */
#define MACTIME_DEVICE_FLAG_STATIC_DROP		(1<<0)
#define MACTIME_DEVICE_FLAG_STATIC_ALLOW	(1<<1)
#define MACTIME_DEVICE_FLAG_DYNAMIC_DROP	(1<<2)
#define MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW	(1<<3)

typedef struct
{
  union
  {
    u8 mac_address[6];
    u64 as_u64;
  };
} mactime_key_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* Timebase */
  clib_timebase_t timebase;

  /* cached sunday midnight */
  f64 sunday_midnight;

  /* Lookup table */
  clib_bihash_8_8_t lookup_table;

  /* Device table */
  mactime_device_t *devices;

  /* Counters */
  vlib_combined_counter_main_t allow_counters;
  vlib_combined_counter_main_t drop_counters;

  /* config parameters */
  u32 lookup_table_num_buckets;
  uword lookup_table_memory_size;
  i32 timezone_offset;

  /* Once-only data structure create flag */
  int feature_initialized;

  /* arp cache copy, for "show mactime" */
  ethernet_arp_ip4_entry_t *arp_cache_copy;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} mactime_main_t;

/* size for an hgw use-case */
#define MACTIME_NUM_BUCKETS	128
#define MACTIME_MEMORY_SIZE	(256<<10)

extern mactime_main_t mactime_main;

extern vlib_node_registration_t mactime_node;
extern vlib_node_registration_t mactime_tx_node;

void mactime_send_create_entry_message (u8 * mac_address);

/* Periodic function events */
#define MACTIME_EVENT1 1
#define MACTIME_EVENT2 2
#define MACTIME_EVENT_PERIODIC_ENABLE_DISABLE 3

#endif /* __included_mactime_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
