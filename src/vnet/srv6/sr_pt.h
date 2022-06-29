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

typedef struct
{
  u32 iface;	   /**< Interface */
  u16 id;	   /**< Interface ID */
  u8 ingress_load; /**< Interface Ingress Load */
  u8 egress_load;  /**< Interface Egress Load */
  u8 tts_template; /**< Interface TTS Template */
} sr_pt_iface_t;

/**
 * @brief SR Path Tracing main datastructure
 */
typedef struct
{
  /* Pool of sr_pt_iface instances */
  sr_pt_iface_t *sr_pt_iface;

  /* Hash table for sr_pt_iface parameters */
  mhash_t sr_pt_iface_index_hash;

} sr_pt_main_t;

extern sr_pt_main_t sr_pt_main;
extern int sr_pt_add_iface (u32 iface, u16 id, u8 ingress_load, u8 egress_load,
			    u8 tts_template);
extern int sr_pt_del_iface (u32 iface);
extern void *sr_pt_find_iface (u32 iface);

#endif /* included_vnet_sr_pt_h */