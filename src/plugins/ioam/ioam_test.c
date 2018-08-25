/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

clib_error_t * vxlan_gpe_ioam_export_vat_plugin_register (vat_main_t * vam);
clib_error_t * pot_vat_plugin_register (vat_main_t *vam);
clib_error_t * trace_vat_plugin_register (vat_main_t * vam);
clib_error_t * vxlan_gpe_vat_plugin_register (vat_main_t * vam);
clib_error_t * udp_ping_vat_plugin_register (vat_main_t * vam);

clib_error_t *
vat_plugin_register (vat_main_t *vam)
{
  clib_error_t *err;

  if ((err = pot_vat_plugin_register (vam)))
    return err;

  if ((err = vxlan_gpe_ioam_export_vat_plugin_register (vam)))
    return err;

  if ((err = trace_vat_plugin_register (vam)))
    return err;

  if ((err = vxlan_gpe_vat_plugin_register(vam)))
    return err;

  if ((err = udp_ping_vat_plugin_register (vam)))
    return err;

  return 0;
}
