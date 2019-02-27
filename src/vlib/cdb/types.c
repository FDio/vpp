/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <stdbool.h>
#include <vppinfra/mhash.h>
#include <vlib/vlib.h>
#include <vlib/cdb/cdb.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#define foreach_number_type       \
  _(u32, u)                       \
  _(u16, u)                       \


#define _(T,f)                                              \
static uword                                                \
cdb_unformat_##T (unformat_input_t * input, va_list * va)   \
{                                                           \
  T *v = va_arg (*va, T *);                                 \
  return unformat (input, "%" #f, v);                       \
}                                                           \
                                                            \
static u8 *                                                 \
cdb_format_##T (u8 * s, va_list * va)                       \
{                                                           \
  T *v = va_arg (*va, T *);                                 \
  return format (s, "%" #f, v[0]);                          \
}
foreach_number_type
#undef _

static uword
cdb_unformat_string (unformat_input_t * input, va_list * va)
{
  char **v = va_arg (*va, char **);
  char *s = 0;

  if (unformat (input, "%s", &s))
    {
      v[0] = s;
      return 1;
    }

  v[0] = 0;
  return 0;
}

static u8 *
cdb_format_string (u8 * s, va_list * va)
{
  char **v = va_arg (*va, char **);
  return format (s, v[0]);
}

static uword
cdb_unformat_bool (unformat_input_t * input, va_list * va)
{
  int *v = va_arg (*va, int *);
  if (unformat (input, "true"))
    v[0] = 1;
  else if (unformat (input, "false"))
    v[0] = 0;
  else
    return 0;
  return 1;
}

static u8 *
cdb_format_bool (u8 * s, va_list * va)
{
  int *v = va_arg (*va, int *);
  return format(s, "%s", v[0] ? "true" : "false");
}

static uword
cdb_unformat_interface_state (unformat_input_t * input, va_list * va)
{
  int *v = va_arg (*va, int *);
  if (unformat (input, "up"))
    v[0] = 1;
  else if (unformat (input, "down"))
    v[0] = 0;
  else
    return 0;
  return 1;
}

static u8 *
cdb_format_interface_state (u8 * s, va_list * va)
{
  int *v = va_arg (*va, int *);
  return format(s, "%s", v[0] ? "up" : "down");
}

/* *INDENT-OFF* */
VLIB_REGISTER_CDB_TYPE (u16) = {
  .name = "u16",
  .size = sizeof (u16),
  .format = cdb_format_u16,
  .unformat = cdb_unformat_u16,
};

VLIB_REGISTER_CDB_TYPE (string) = {
  .name = "string",
  .size = sizeof (void *),
  .format = cdb_format_string,
  .unformat = cdb_unformat_string,
  .is_pointer_type = 1,
};

VLIB_REGISTER_CDB_TYPE (u32) = {
  .name = "u32",
  .size = sizeof (u32),
  .format = cdb_format_u32,
  .unformat = cdb_unformat_u32,
};

VLIB_REGISTER_CDB_TYPE (bool) = {
  .name = "bool",
  .size = sizeof (int),
  .format = cdb_format_bool,
  .unformat = cdb_unformat_bool,
};

VLIB_REGISTER_CDB_TYPE (pci_addr) = {
  .name = "pci-addr",
  .size = sizeof (vlib_pci_addr_t),
  .format = format_vlib_pci_addr,
  .unformat = unformat_vlib_pci_addr,
};

VLIB_REGISTER_CDB_TYPE (mac_addr) = {
  .name = "mac-addr",
  .size = 6,
  .format = format_mac_address,
  .unformat = unformat_mac_address,
};

VLIB_REGISTER_CDB_TYPE (interface_state) = {
  .name = "interface-state",
  .size = sizeof (int),
  .format = cdb_format_interface_state,
  .unformat = cdb_unformat_interface_state,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
