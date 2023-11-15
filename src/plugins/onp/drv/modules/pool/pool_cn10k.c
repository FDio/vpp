/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pool/pool_priv.h>

const cnxk_pool_ops_t pool_10k_ops = {
  .info_dump = cnxk_pool_info_dump,
  .range_set = cnxk_pool_range_set,
  .info_get = cnxk_pool_info_get,
  .alloc = cnxk_pool_elem_alloc,
  .free = cnxk_pool_elem_free,
  .create = cnxk_pool_create,
  .setup = cnxk_pool_setup,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
