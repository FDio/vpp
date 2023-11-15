/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief OCTEON native plugin interface.
 */

#ifndef included_onp_onp_h
#define included_onp_onp_h

#include <assert.h>
#define __USE_GNU
#include <dlfcn.h>
#include <stdbool.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/plugin/plugin.h>
#include <vnet/flow/flow.h>
#include <vnet/udp/udp.h>

#include <onp/drv/inc/common.h>

#include <onp/pool/buffer.h>
#include <onp/pktio/pktio.h>

#define ONP_INIT_MAGIC_NUM 0xdeadbeaf
#define onp_get_main()	   &onp_main

#define onp_pktio_err	 cnxk_pktio_err
#define onp_pktio_warn	 cnxk_pktio_warn
#define onp_pktio_notice cnxk_pktio_notice
#define onp_pktio_debug	 cnxk_pktio_debug

#define onp_pool_err	cnxk_pool_err
#define onp_pool_warn	cnxk_pool_warn
#define onp_pool_notice cnxk_pool_notice
#define onp_pool_debug	cnxk_pool_debug

typedef struct
{
  /* Pktio */
  onp_pktio_config_t onp_pktioconf_default;
  onp_pktio_config_t *onp_pktioconfs;
  uword *onp_pktio_config_index_by_pci_addr;

  /* Pool */
  u32 onp_num_pkt_buf;
  i16 onp_pktpool_refill_deplete_sz;
} onp_config_main_t;

/* clang-format off */

/*
 * Plugin generic counters
 * All of them are simple counters
 */

/* counter, name, verbose */
#define foreach_onp_counters                                                                                  \
  _ (0, pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].refill,              "default-pool-refill-count", 1)             \
  _ (1, pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].deplete,             "default-pool-deplete-count", 1)

/* clang-format on */

#define foreach_pool_counter_names                                            \
  _ (refill)                                                                  \
  _ (deplete)

typedef struct
{
#define _(s) vlib_simple_counter_main_t s##_counters;
  foreach_pool_counter_names
#undef _
} onp_pool_counters_t;

typedef struct
{
  onp_pool_counters_t pool[CNXK_POOL_COUNTER_TYPE_MAX];
} onp_counters_t;

/* Total number of counters in onp_counters_t */
#define ONP_MAX_COUNTERS                                                      \
  sizeof (onp_counters_t) / sizeof (vlib_simple_counter_main_t)

STATIC_ASSERT (ONP_MAX_COUNTERS <= 64,
	       "ONP_MAX_COUNTERS is larger than api counter array size");
typedef struct
{
  /* Fast path per thread data */
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  cnxk_per_thread_data_t *onp_per_thread_data;

  /* Fast path pktio structure */
  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  onp_pktio_t *onp_pktios;

  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  u8 *cnxk_pool_by_buffer_pool_index;

  u8 *buffer_pool_by_cnxk_pool_index;

  u16 onp_pktio_count;

  /* Startup config */
  onp_config_main_t *onp_conf;

  /* API message ID base */
  u16 onp_msg_id_base;

  u8 onp_init_done;

  onp_counters_t onp_counters;
} onp_main_t;

extern onp_config_main_t onp_config_main;
extern onp_main_t onp_main;

const char *onp_address_to_str (void *p);

clib_error_t *cnxk_plt_model_init ();

clib_error_t *onp_pktio_config_parse (onp_config_main_t *conf,
				      vlib_pci_addr_t pci_addr,
				      unformat_input_t *input, u32 is_default);

clib_error_t *onp_pktio_configs_validate (vlib_main_t *vm,
					  onp_config_main_t *conf);

clib_error_t *onp_pktio_early_setup (vlib_main_t *vm, onp_main_t *om,
				     onp_pktio_config_t *pconf,
				     onp_pktio_t **ppktio);

clib_error_t *onp_pktio_setup (vlib_main_t *vm, onp_main_t *om,
			       onp_pktio_config_t *pconf,
			       onp_pktio_t **ppktio);

clib_error_t *onp_pktio_link_state_update (onp_pktio_t *od);

unsigned int onp_get_per_thread_stats (u64 **stat, u64 *pool_stat,
				       u32 n_threads, u8 verbose, u8 *is_valid,
				       u64 *threads_with_stats);

#endif /* included_onp_onp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
