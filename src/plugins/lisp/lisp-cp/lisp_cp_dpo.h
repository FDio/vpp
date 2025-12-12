/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __LISP_CP_DPO_H__
#define __LISP_CP_DPO_H__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of punt to the LISP control plane.
 */
typedef struct lisp_cp_dpo_t
{
  /**
   * The transport payload type.
   */
  dpo_proto_t lcd_proto;
} lisp_cp_dpo_t;

extern const dpo_id_t *lisp_cp_dpo_get (dpo_proto_t proto);

extern void lisp_cp_dpo_module_init (void);

#endif
