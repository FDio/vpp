/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/dma/dma.h>

VLIB_REGISTER_LOG_CLASS (dma_log) = {
  .class_name = "dma",
};

vlib_dma_main_t vlib_dma_main = {};

clib_error_t *
vlib_dma_register_backend (vlib_main_t *vm, vlib_dma_backend_t *b)
{
  vlib_dma_main_t *dm = &vlib_dma_main;
  vec_add1 (dm->backends, *b);
  dma_log_info ("backend '%s' registered", b->name);
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
      dma_log_info ("calling '%s' config_add_fn", b->name);
      if (b->config_add_fn (vm, cd))
	{
	  dma_log_info ("config %u added into backend %s", cd - dm->configs,
			b->name);
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
  dma_log_info ("config %u deleted from backend %s", config_index, b->name);
}

u8 *
vlib_dma_config_info (u8 *s, va_list *args)
{
  vlib_dma_main_t *dm = &vlib_dma_main;
  int config_index = va_arg (*args, int);
  u32 len = pool_elts (dm->configs);
  if (config_index >= len)
    return format (s, "%s", "not found");
  vlib_dma_config_data_t *cd = pool_elt_at_index (dm->configs, config_index);

  vlib_dma_backend_t *b = vec_elt_at_index (dm->backends, cd->backend_index);

  if (b->info_fn)
    return b->info_fn (s, args);

  return 0;
}
