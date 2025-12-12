/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

clib_error_t *vat_plugin_register_one (vat_main_t * vam);
clib_error_t *vat_plugin_register_cp (vat_main_t * vam);
clib_error_t *vat_plugin_register_gpe (vat_main_t * vam);

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  clib_error_t *err;

  if ((err = vat_plugin_register_gpe (vam)))
    return err;
  if ((err = vat_plugin_register_cp (vam)))
    return err;
  if ((err = vat_plugin_register_one (vam)))
    return err;

  return NULL;
}
