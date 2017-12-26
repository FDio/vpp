/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#define MVCONF_DBG_LEVEL 0
#define MVCONF_PP2_BPOOL_COOKIE_SIZE 32
#define MVCONF_PP2_BPOOL_DMA_ADDR_SIZE 64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE 64
#define MVCONF_SYS_DMA_UIO
#define MVCONF_TYPES_PUBLIC
#define MVCONF_DMA_PHYS_ADDR_T_PUBLIC

#include "mv_std.h"
#include "env/mv_sys_dma.h"
#include "drivers/mv_pp2.h"
#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_ppio.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  struct pp2_bpool *bpool;
} ppv2_inq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  u32 *buffers;
  u16 head;
  u16 tail;
} ppv2_outq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
#define PPV2_IF_F_ADMIN_UP (1 << 0)
  struct pp2_ppio *ppio;
  u32 per_interface_next_index;

  ppv2_inq_t *inqs;
  ppv2_outq_t *outqs;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
} ppv2_if_t;

#define PPV2_BUFF_BATCH_SZ 64

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct pp2_hif *hif;
  struct pp2_ppio_desc *descs;
  struct buff_release_entry bre[PPV2_BUFF_BATCH_SZ];
  u32 buffers[PPV2_BUFF_BATCH_SZ];
} ppv2_per_thread_data_t;

typedef struct
{
  ppv2_if_t *interfaces;
  ppv2_per_thread_data_t *per_thread_data;
} ppv2_main_t;

extern vnet_device_class_t ppv2_device_class;
extern ppv2_main_t ppv2_main;

typedef struct
{
  u8 *name;
  u16 rx_q_sz;
  u16 tx_q_sz;

  /* return */
  int rv;
  clib_error_t *error;
} ppv2_create_if_args_t;

void ppv2_create_if (ppv2_create_if_args_t * args);
void ppv2_delete_if (ppv2_if_t * dfif);

/* output.c */

#define foreach_ppv2_tx_func_error \
  _(NO_FREE_SLOTS, "no free tx slots")			\
  _(PPIO_SEND, "pp2_ppio_send errors")			\
  _(PPIO_GET_NUM_OUTQ_DONE, "pp2_ppio_get_num_outq_done errors")

typedef enum
{
#define _(f,s) PPV2_TX_ERROR_##f,
  foreach_ppv2_tx_func_error
#undef _
    PPV2_TX_N_ERROR,
} ppv2_tx_func_error_t;

uword ppv2_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame);

/* input.c */

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  struct pp2_ppio_desc desc;
} ppv2_input_trace_t;

extern vlib_node_registration_t ppv2_input_node;

/* format.c */
format_function_t format_ppv2_input_trace;
format_function_t format_ppv2_interface;
format_function_t format_ppv2_interface_name;


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
