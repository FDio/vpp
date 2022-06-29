/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Path Tracing data structures definitions
 *
 */

#ifndef included_vnet_pt_h
#define included_vnet_pt_h

/*PT error codes*/
#define PT_ERR_NOENT		    -1 /* No such entry*/
#define PT_ERR_EXIST		    -2 /* Entry exists */
#define PT_ERR_IFACE_INVALID	    -3 /* IFACE invalid */
#define PT_ERR_ID_INVALID	    -4 /* ID invalid */
#define PT_ERR_LOAD_INVALID	    -5 /* LOAD invalid*/
#define PT_ERR_TTS_TEMPLATE_INVALID -6 /* TTS Template invalid */

/*PT paramters max values*/
#define PT_ID_MAX	    4095
#define PT_LOAD_MAX	    15
#define PT_TTS_TEMPLATE_MAX 3

/*PT TTS Templates*/
#define PT_TTS_TEMPLATE_0	0
#define PT_TTS_TEMPLATE_1	1
#define PT_TTS_TEMPLATE_2	2
#define PT_TTS_TEMPLATE_3	3
#define PT_TTS_TEMPLATE_DEFAULT 2

/*PT TTS Template shift value*/
#define PT_TTS_SHIFT_TEMPLATE_0 8
#define PT_TTS_SHIFT_TEMPLATE_1 12
#define PT_TTS_SHIFT_TEMPLATE_2 16
#define PT_TTS_SHIFT_TEMPLATE_3 20

typedef struct
{
  u32 iface;	   /**< Interface */
  u16 id;	   /**< Interface ID */
  u8 ingress_load; /**< Interface Ingress Load */
  u8 egress_load;  /**< Interface Egress Load */
  u8 tts_template; /**< Interface TTS Template */
} __attribute__ ((packed)) pt_iface_t;

/**
 * @brief Path Tracing main datastructure
 */
typedef struct
{
  /* Pool of pt_iface instances */
  pt_iface_t *pt_iface;

  /* Hash table for pt iface parameters */
  mhash_t pt_iface_index_hash;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} pt_main_t;

extern pt_main_t pt_main;
extern int pt_add_iface (u32 iface, u16 id, u8 ingress_load, u8 egress_load,
			 u8 tts_template);
extern int pt_del_iface (u32 iface);
extern void *pt_find_iface (u32 iface);

#endif /* included_vnet_pt_h */

/*
 * * fd.io coding-style-patch-verification: ON
 * *
 * * Local Variables:
 * * eval: (c-set-style "gnu")
 * * End:
 * */
