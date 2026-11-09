/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <base/roc_api.h>

#define OCT_BAR_ALIGN	     (ROC_AURA_ID_MASK + 1)
#define OCT_BAR_DEFAULT_SIZE (32ULL << 20)

typedef enum
{
  OCT_DEVICE_TYPE_UNKNOWN = 0,
  OCT_DEVICE_TYPE_RVU_PF,
  OCT_DEVICE_TYPE_RVU_VF,
  OCT_DEVICE_TYPE_LBK_VF,
  OCT_DEVICE_TYPE_SDP_VF,
  OCT_DEVICE_TYPE_O10K_CPT_VF,
  OCT_DEVICE_TYPE_O9K_CPT_VF,
} __clib_packed oct_device_type_t;

#define OCT_DEVTYPE_IS_VF(type)                                                                    \
  ((type) == OCT_DEVICE_TYPE_RVU_VF || (type) == OCT_DEVICE_TYPE_LBK_VF ||                         \
   (type) == OCT_DEVICE_TYPE_SDP_VF || (type) == OCT_DEVICE_TYPE_O10K_CPT_VF ||                    \
   (type) == OCT_DEVICE_TYPE_O9K_CPT_VF)

#define OCT_DEVTYPE_IS_CPT(type)                                                                   \
  ((type) == OCT_DEVICE_TYPE_O10K_CPT_VF || (type) == OCT_DEVICE_TYPE_O9K_CPT_VF)

/* must be the first member of the driver specific device structure */
typedef struct
{
  oct_device_type_t type;
  struct plt_pci_device plt_pci_dev;
  oct_msix_handler_info_t *msix_handler;
} oct_dev_common_t;

extern oct_plt_init_param_t oct_plt_init_param;
extern struct roc_model oct_model;

u8 *oct_dev_probe (vnet_dev_probe_args_t *args, int cpt);
vnet_dev_rv_t oct_dev_pci_init (vlib_main_t *vm, vnet_dev_t *dev, int cpt);
vnet_dev_rv_t oct_roc_init (void);
vnet_dev_rv_t cnx_return_roc_err (vnet_dev_t *dev, int rrv, char *fmt, ...);

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, oct_log.class, "%U: " f, format_vnet_dev_addr, (dev),            \
	    ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, oct_log.class, "%U: " f, format_vnet_dev_addr, (dev),             \
	    ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, oct_log.class, "%U: " f, format_vnet_dev_addr, (dev),           \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, oct_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, oct_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)
