/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

clib_error_t * vat_plugin_register_one (vat_main_t * vam);
clib_error_t * vat_plugin_register_cp (vat_main_t * vam);
clib_error_t * vat_plugin_register_gpe (vat_main_t * vam);

clib_error_t *
vat_plugin_register (vat_main_t *vam)
{
  clib_error_t *err;

  if ((err = vat_plugin_register_gpe (vam)))
    return err;
  if ((err = vat_plugin_register_cp(vam)))
    return err;
  if ((err = vat_plugin_register_one (vam)))
    return err;

  return NULL;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
