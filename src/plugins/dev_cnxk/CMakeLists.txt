# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.


set(ROC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${ROC_DIR})

add_vpp_plugin(dev_cnxk
  SOURCES
  cnxk.c
  format.c
  port.c
  queue.c
  rx_node.c
  tx_node.c

  ${ROC_DIR}/roc/base/roc_cpt.c
  ${ROC_DIR}/roc/base/roc_dev.c
  ${ROC_DIR}/roc/base/roc_idev.c
  ${ROC_DIR}/roc/base/roc_irq.c
  ${ROC_DIR}/roc/base/roc_mbox.c
  ${ROC_DIR}/roc/base/roc_model.c
  ${ROC_DIR}/roc/base/roc_nix.c
  ${ROC_DIR}/roc/base/roc_nix_debug.c
  ${ROC_DIR}/roc/base/roc_nix_fc.c
  ${ROC_DIR}/roc/base/roc_nix_inl.c
  ${ROC_DIR}/roc/base/roc_nix_irq.c
  ${ROC_DIR}/roc/base/roc_nix_mac.c
  ${ROC_DIR}/roc/base/roc_nix_npc.c
  ${ROC_DIR}/roc/base/roc_nix_ops.c
  ${ROC_DIR}/roc/base/roc_nix_queue.c
  ${ROC_DIR}/roc/base/roc_nix_rss.c
  ${ROC_DIR}/roc/base/roc_nix_tm.c
  ${ROC_DIR}/roc/base/roc_nix_tm_mark.c
  ${ROC_DIR}/roc/base/roc_nix_tm_ops.c
  ${ROC_DIR}/roc/base/roc_nix_tm_utils.c
  ${ROC_DIR}/roc/base/roc_npa.c
  ${ROC_DIR}/roc/base/roc_npa_debug.c
  ${ROC_DIR}/roc/base/roc_npa_irq.c
  ${ROC_DIR}/roc/base/roc_npa_type.c
  ${ROC_DIR}/roc/base/roc_npc.c
  ${ROC_DIR}/roc/base/roc_npc_mcam.c
  ${ROC_DIR}/roc/base/roc_utils.c
  ${ROC_DIR}/roc/init.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

