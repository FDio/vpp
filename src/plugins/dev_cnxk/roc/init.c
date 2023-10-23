/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <roc/base/roc_api.h>

vlib_log_class_t cnxk_logtype_base;
vlib_log_class_t cnxk_logtype_cpt;
vlib_log_class_t cnxk_logtype_mbox;
vlib_log_class_t cnxk_logtype_npa;
vlib_log_class_t cnxk_logtype_nix;
vlib_log_class_t cnxk_logtype_sso;
vlib_log_class_t cnxk_logtype_npc;
vlib_log_class_t cnxk_logtype_tm;
vlib_log_class_t cnxk_logtype_tim;
vlib_log_class_t cnxk_logtype_pci;
vlib_log_class_t cnxk_logtype_ep;
vlib_log_class_t cnxk_logtype_bphy;
vlib_log_class_t cnxk_logtype_iomem;
vlib_log_class_t cnxk_logtype_ml;

int
cnxk_plt_init (void)
{

  cnxk_logtype_base = vlib_log_register_class ("onp", "roc");

  cnxk_logtype_cpt = vlib_log_register_class ("onp", "roc_cpt");

  cnxk_logtype_mbox = vlib_log_register_class ("onp", "roc_mbox");

  cnxk_logtype_npa = vlib_log_register_class ("onp", "roc_npa");

  cnxk_logtype_nix = vlib_log_register_class ("onp", "roc_nix");

  cnxk_logtype_sso = vlib_log_register_class ("onp", "roc_sso");

  cnxk_logtype_npc = vlib_log_register_class ("onp", "roc_npc");

  cnxk_logtype_tm = vlib_log_register_class ("onp", "roc_tm");

  cnxk_logtype_tim = vlib_log_register_class ("onp", "roc_tim");

  cnxk_logtype_pci = vlib_log_register_class ("onp", "roc_pci");

  cnxk_logtype_ep = vlib_log_register_class ("onp", "roc_ep");

  cnxk_logtype_bphy = vlib_log_register_class ("onp", "roc_bphy");

  cnxk_logtype_iomem = vlib_log_register_class ("onp", "roc_iomem");

  cnxk_logtype_ml = vlib_log_register_class ("onp", "roc_ml");

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
