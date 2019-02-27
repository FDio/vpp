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

static clib_error_t *
show_cdb_types (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cdb_main_t *cm = &cdb_main;
  clib_error_t *error = 0;
  vlib_cdb_type_t *t;

  if (cm->types == 0)
    return 0;

  vlib_cli_output (vm, "%-20s%-5s", "Name", "Size");
  vec_foreach (t, cm->types)
    {
      vlib_cli_output (vm, "%-20s%-5u", t->name, t->size);
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_cdb_types, static) = {
  .path = "show cdb types",
  .short_help = "show cdb types",
  .function = show_cdb_types,
};
/* *INDENT-ON* */

static u8 *
format_cdb_class (u8 * s, va_list * va)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_class_t *c = va_arg (*va, vlib_cdb_class_t *);
  vlib_cdb_class_item_t *i;

  s = format (s, "Class '%s'", c->name);
  s = format (s, "\n  Index %u", c->index);
  s = format (s, "\n  Items:");
  s = format (s, "\n    %-20s%-20s%s", "Item Name", "Type", "Description");

  vec_foreach (i, c->items)
    {
      vlib_cdb_type_t *t = vec_elt_at_index (cm->types, i->type_index);
      s = format (s, "\n    %-20s%-20s%s", i->name, t->name, i->description);
    }

  return s;
}


static clib_error_t *
show_cdb_classes (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cdb_main_t *cm = &cdb_main;
  clib_error_t *error = 0;
  vlib_cdb_class_t *c;

  if (cm->classes == 0)
    return 0;

  vec_foreach (c, cm->classes)
    {
      if (c != cm->classes)
        vlib_cli_output (vm, "\n");
      vlib_cli_output (vm, "%U\n", format_cdb_class, c);
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_cdb_classes, static) = {
  .path = "show cdb classes",
  .short_help = "show cdb classes",
  .function = show_cdb_classes,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
