/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_pktio_fp_defs_h
#define included_onp_drv_inc_pktio_fp_defs_h

#define foreach_onp_pktio_input_error _ (NONE, "No error")

/* clang-format off */
typedef enum
{
#define _(sym, str) ONP_PKTIO_INPUT_ERROR_##sym,
  foreach_onp_pktio_input_error
#undef _
} onp_pktio_input_error_t;
/* clang-format on */

#endif /* included_onp_drv_inc_pktio_fp_defs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
