/*
 * trace_util.h -- Trace Profile Utility header
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef include_vnet_trace_util_h
#define include_vnet_trace_util_h

#define debug_ioam debug_ioam_fn


/**
 * Usage:
 *
 * On any node that participates in iOAM Trace.
 *
 * Step 1: Initialize this library by calling trace_init()
 * Step 2: Setup a trace  profile that contains all the parameters needed to compute cumulative:
 *         Call these functions:
 *         trace_profile_find
 *         trace_profile_create
 * Step 2a: On initial node enable the profile to be used:
 *          trace_profile_set_active / trace_profile_get_active will return the profile
 * Step 4: TBD
 *         trace_validate
 *
 */

typedef struct trace_profile_
{
  u8 valid:1;
  u8 trace_type;
  u8 num_elts;
  /* Configured node-id */
  u32 node_id;
  u32 app_data;
  u32 trace_tsp;
} trace_profile;

typedef struct
{
  /* Name of the default profile list in use */
  trace_profile profile;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} trace_main_t;


/*
 * Initialize Trace profile
 */
int trace_util_init (void);


/* setup and clean up profile */
int trace_profile_create (trace_profile * profile, u8 trace_type, u8 num_elts,
			  u32 trace_tsp, u32 node_id, u32 app_data);

void clear_trace_profiles (void);

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  u8 ioam_trace_type;
  u8 data_list_elts_left;
  u32 elts[0]; /* Variable type. So keep it generic */
}) ioam_trace_hdr_t;
/* *INDENT-ON* */



#define    BIT_TTL_NODEID       (1<<0)
#define    BIT_ING_INTERFACE    (1<<1)
#define    BIT_EGR_INTERFACE    (1<<2)
#define    BIT_TIMESTAMP        (1<<3)
#define    BIT_APPDATA          (1<<4)
#define    BIT_LOOPBACK         (1<<5)
#define    BIT_LOOPBACK_REPLY   (1<<6)
#define    TRACE_TYPE_MASK      0x7F	/* Mask of all above bits */

#define    TRACE_TYPE_IF_TS_APP_LOOP    0x3F

/*
     0x00011111  iOAM-trace-type is 0x00011111 then the format of node
        data is:

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     ingress_if_id             |         egress_if_id          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                            app_data                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define   TRACE_TYPE_IF_TS_APP   0x1f
typedef struct
{
  u32 ttl_node_id;
  u16 ingress_if;
  u16 egress_if;
  u32 timestamp;
  u32 app_data;
} ioam_trace_if_ts_app_t;

/*
     0x00000111  iOAM-trace-type is 0x00000111 then the format is:

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     ingress_if_id             |         egress_if_id          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define   TRACE_TYPE_IF   0x03
typedef struct
{
  u32 ttl_node_id;
  u16 ingress_if;
  u16 egress_if;
} ioam_trace_if_t;

/*
     0x00001001  iOAM-trace-type is 0x00001001 then the format is:

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define   TRACE_TYPE_TS   0x09
typedef struct
{
  u32 ttl_node_id;
  u32 timestamp;
} ioam_trace_ts_t;

/*
     0x00010001  iOAM-trace-type is 0x00010001 then the format is:


          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                            app_data                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


#define   TRACE_TYPE_APP   0x11
typedef struct
{
  u32 ttl_node_id;
  u32 app_data;
} ioam_trace_app_t;

/*

     0x00011001  iOAM-trace-type is 0x00011001 then the format is:

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Hop_Lim     |              node_id                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +                           timestamp                           +
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                            app_data                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define   TRACE_TYPE_TS_APP   0x19
typedef struct
{
  u32 ttl_node_id;
  u32 timestamp;
  u32 app_data;
} ioam_trace_ts_app_t;

static inline u8
fetch_trace_data_size (u16 trace_type)
{
  u8 trace_data_size = 0;

  if ((trace_type & TRACE_TYPE_IF_TS_APP) == TRACE_TYPE_IF_TS_APP)
    trace_data_size = sizeof (ioam_trace_if_ts_app_t);
  else if ((trace_type & TRACE_TYPE_IF) == TRACE_TYPE_IF)
    trace_data_size = sizeof (ioam_trace_if_t);
  else if ((trace_type & TRACE_TYPE_TS) == TRACE_TYPE_TS)
    trace_data_size = sizeof (ioam_trace_ts_t);
  else if ((trace_type & TRACE_TYPE_APP) == TRACE_TYPE_APP)
    trace_data_size = sizeof (ioam_trace_app_t);
  else if ((trace_type & TRACE_TYPE_TS_APP) == TRACE_TYPE_TS_APP)
    trace_data_size = sizeof (ioam_trace_ts_app_t);

  return trace_data_size;
}

always_inline void
ioam_trace_set_bit (ioam_trace_hdr_t * trace_hdr, u8 trace_bit)
{
  trace_hdr->ioam_trace_type |= trace_bit;
}

always_inline void
ioam_trace_reset_bit (ioam_trace_hdr_t * trace_hdr, u8 trace_bit)
{
  trace_hdr->ioam_trace_type &= (~trace_bit);
}

int ioam_trace_get_sizeof_handler (u32 * result);
int ip6_trace_profile_setup (void);
int ip6_trace_profile_cleanup (void);

#define TSP_SECONDS              0
#define TSP_MILLISECONDS         1
#define TSP_MICROSECONDS         2
#define TSP_NANOSECONDS          3

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
