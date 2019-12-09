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
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

clib_error_t * vxlan_gpe_ioam_export_vat_plugin_register (vat_main_t * vam);
clib_error_t * pot_vat_plugin_register (vat_main_t *vam);
clib_error_t * trace_vat_plugin_register (vat_main_t * vam);
clib_error_t * vxlan_gpe_vat_plugin_register (vat_main_t * vam);
clib_error_t * udp_ping_vat_plugin_register (vat_main_t * vam);
clib_error_t * ioam_export_vat_plugin_register (vat_main_t * vam);

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

  if ((err = ioam_export_vat_plugin_register (vam)))
    return err;

  return 0;
}
uword unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat(input, "%U", unformat_ip4_address, &ip46->ip4)) {
    ip46_address_mask_ip4(ip46);
    return 1;
  } else if ((type != IP46_TYPE_IP4) &&
      unformat(input, "%U", unformat_ip6_address, &ip46->ip6)) {
    return 1;
  }
  return 0;
}
