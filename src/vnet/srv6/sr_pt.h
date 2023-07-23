/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

/**
 * @file
 * @brief SR Path Tracing data structures definitions
 *
 */

#ifndef included_vnet_sr_pt_h
#define included_vnet_sr_pt_h

#define IP6_HBH_PT_TYPE 50

/*SR PT error codes*/
#define SR_PT_ERR_NOENT		       -1 /* No such entry*/
#define SR_PT_ERR_EXIST		       -2 /* Entry exists */
#define SR_PT_ERR_IFACE_INVALID	       -3 /* IFACE invalid */
#define SR_PT_ERR_ID_INVALID	       -4 /* ID invalid */
#define SR_PT_ERR_LOAD_INVALID	       -5 /* LOAD invalid*/
#define SR_PT_ERR_TTS_TEMPLATE_INVALID -6 /* TTS Template invalid */

/*SR PT paramters max values*/
#define SR_PT_ID_MAX	       4095
#define SR_PT_LOAD_MAX	       15
#define SR_PT_TTS_TEMPLATE_MAX 3

/*SR PT TTS Templates*/
#define SR_PT_TTS_TEMPLATE_0	   0
#define SR_PT_TTS_TEMPLATE_1	   1
#define SR_PT_TTS_TEMPLATE_2	   2
#define SR_PT_TTS_TEMPLATE_3	   3
#define SR_PT_TTS_TEMPLATE_DEFAULT 2

/*SR PT TTS Template shift value*/
#define SR_PT_TTS_SHIFT_TEMPLATE_0 8
#define SR_PT_TTS_SHIFT_TEMPLATE_1 12
#define SR_PT_TTS_SHIFT_TEMPLATE_2 16
#define SR_PT_TTS_SHIFT_TEMPLATE_3 20

/*PT node behaviors*/
#define PT_BEHAVIOR_SRC 0
#define PT_BEHAVIOR_MID 1
#define PT_BEHAVIOR_SNK 2

typedef struct
{
  u32 iface;	   /**< Interface */
  u16 id;	   /**< Interface ID */
  u8 ingress_load; /**< Interface Ingress Load */
  u8 egress_load;  /**< Interface Egress Load */
  u8 tts_template; /**< Interface TTS Template */
} sr_pt_iface_t;

typedef struct
{
  u32 iface;  /**< Interface */
} sr_pt_probe_inject_iface_t;

typedef struct
{
  u16 oif_oil;
  u8 tts;
} __clib_packed sr_pt_cmd_t;

typedef struct
{
  sr_pt_cmd_t cmd_stack[12];
} __clib_packed ip6_hop_by_hop_option_pt_t;

/**
 * @brief SR Path Tracing main datastructure
 */
typedef struct
{
  /* Pool of sr_pt_iface instances */
  sr_pt_iface_t *sr_pt_iface;

  /* Hash table for sr_pt_iface parameters */
  mhash_t sr_pt_iface_index_hash;

  /* Pool of sr_pt_probe_inject_iface instances */
  sr_pt_probe_inject_iface_t *sr_pt_probe_inject_iface;

  /* Hash table for sr_pt_probe_inject_iface parameters */
  mhash_t sr_pt_probe_inject_iface_index_hash;

  /* convenience */
  u16 msg_id_base;
} sr_pt_main_t;

extern sr_pt_main_t sr_pt_main;
extern vlib_node_registration_t sr_pt_node;
extern int sr_pt_add_iface (u32 iface, u16 id, u8 ingress_load, u8 egress_load,
			    u8 tts_template);
extern int sr_pt_del_iface (u32 iface);
extern void *sr_pt_find_iface (u32 iface);
extern int sr_pt_add_probe_inject_iface (u32 iface);
extern int sr_pt_del_probe_inject_iface (u32 iface);
extern void *sr_pt_find_probe_inject_iface (u32 iface);

#endif /* included_vnet_sr_pt_h */