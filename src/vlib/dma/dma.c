/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/dma/dma.h>

VLIB_REGISTER_LOG_CLASS (dma_log) = {
  .class_name = "dma",
};

#define log_debug(f, ...)                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dma_log.class, "%s: " f, __func__,          \
	    ##__VA_ARGS__)

vlib_dma_main_t vlib_dma_main = {};

clib_error_t *
vlib_dma_register_backend (vlib_main_t *vm, vlib_dma_backend_t *b)
{
  vlib_dma_main_t *dm = &vlib_dma_main;
  vec_add1 (dm->backends, *b);
  log_debug ("Backend '%s' registered", b->name);
  return 0;
}

int
vlib_dma_config_add (vlib_main_t *vm, vlib_dma_config_t *c)
{
  vlib_dma_main_t *dm = &vlib_dma_main;
  vlib_dma_backend_t *b;
  vlib_dma_config_data_t *cd;

  pool_get_zero (dm->configs, cd);
  cd->config_index = cd - dm->configs;

  clib_memcpy (&cd->cfg, c, sizeof (vlib_dma_config_t));

  vec_foreach (b, dm->backends)
    {
      log_debug ("calling '%s' config_add_fn", b->name);
      if (b->config_add_fn (vm, cd))
	{
	  log_debug ("config %u added", cd - dm->configs);
	  cd->backend_index = b - dm->backends;
	  return cd - dm->configs;
	}
    }

  pool_put (dm->configs, cd);
  return -1;
}

void
vlib_dma_config_del (vlib_main_t *vm, u32 config_index)
{
  vlib_dma_main_t *dm = &vlib_dma_main;
  vlib_dma_config_data_t *cd = pool_elt_at_index (dm->configs, config_index);
  vlib_dma_backend_t *b = vec_elt_at_index (dm->backends, cd->backend_index);

  if (b->config_del_fn)
    b->config_del_fn (vm, cd);

  pool_put (dm->configs, cd);
  log_debug ("config %u added", config_index);
}
