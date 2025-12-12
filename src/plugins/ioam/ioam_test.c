/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
