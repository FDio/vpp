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
#include <vlib/cdb/format.h>

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

static clib_error_t *
cdb_create_class_object_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *class_name = 0, *obj_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%s %s", &class_name, &obj_name))
    ;
  else
    {
      error = clib_error_return (0, "parse error: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rc = vlib_cdb_create_class_object (class_name, obj_name);
  if (rc < 0)
    error = clib_error_return (0, "cdb: failed to create obj '%s'", obj_name);

done:
  unformat_free (line_input);
  vec_free (class_name);
  vec_free (obj_name);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_create_cdb_class_object, static) = {
  .path = "cdb create",
  .short_help = "cdb create <class-name> <obj-name>",
  .function = cdb_create_class_object_fn,
};
/* *INDENT-ON* */

static void
cdb_show_config_datastore (vlib_main_t *vm,
    vlib_cdb_config_datastore_t *ds,
    int is_candidate)
{
  vlib_cdb_object_t *o;

  /* *INDENT-OFF* */
  pool_foreach (o, ds->objs,
  ({
    vlib_cli_output (vm, "%U\n", format_cdb_object, o, is_candidate);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
cdb_show_running_config_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vlib_cdb_config_datastore_t *ds = vlib_cdb_get_running_ds ();
  cdb_show_config_datastore (vm, ds, 0);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_running_config, static) = {
  .path = "show cdb running-config",
  .short_help = "show cdb running-config",
  .function = cdb_show_running_config_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_commit_fn (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cdb_commit ();
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_cdb_commit_config, static) = {
  .path = "cdb commit",
  .short_help = "cdb commit",
  .function = cdb_commit_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_show_candidate_config_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  vlib_cdb_config_datastore_t *ds = vlib_cdb_get_candidate_ds ();
  cdb_show_config_datastore (vm, ds, 1);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_cadidate_config, static) = {
  .path = "show cdb candidate-config",
  .short_help = "show cdb candidate-config",
  .function = cdb_show_candidate_config_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_delete_class_object_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *class_name = 0, *obj_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%s %s", &class_name, &obj_name))
    ;
  else
    {
      error = clib_error_return (0, "parse error: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rc = vlib_cdb_delete_class_object (class_name, obj_name);
  if (rc < 0)
    error = clib_error_return (0, "cdb: failed to delete obj '%s'", obj_name);

done:
  unformat_free (line_input);
  vec_free (class_name);
  vec_free (obj_name);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_delete_class_object, static) = {
  .path = "cdb delete",
  .short_help = "cdb delete <class-name> <object-name>",
  .function = cdb_delete_class_object_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_edit_class_object_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *class_name = 0, *obj_name = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%s %s", &class_name, &obj_name))
    ;
  else
    {
      error = clib_error_return (0, "parse error: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rc = vlib_cdb_edit_class_object (class_name, obj_name);
  if (rc < 0)
    error = clib_error_return (0, "cdb: failed to edit obj '%s'", obj_name);

done:
  unformat_free (line_input);
  vec_free (class_name);
  vec_free (obj_name);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_edit_class_object, static) = {
  .path = "cdb edit",
  .short_help = "cdb edit <class-name> <object-name>",
  .function = cdb_edit_class_object_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_set_field_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{

  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *field = 0, *value = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%s %s", &field, &value))
    ;
  else
    {
      error = clib_error_return (0, "parse error: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rc = vlib_cdb_set_field_value (field, value);
  if (rc < 0)
    error = clib_error_return (0, "cdb: failed to set field '%s'", field);

done:
  unformat_free (line_input);
  vec_free (field);
  vec_free (value);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_cdb_set_field , static) = {
  .path = "cdb set",
  .short_help = "cdb set <field> <value>",
  .function = cdb_set_field_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_clear_candidate_config_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cdb_clear_candidate_config ();
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_cdb_clear_candidate_config, static) = {
  .path = "cdb clear candidate-config",
  .short_help = "clear candidate config",
  .function = cdb_clear_candidate_config_fn,
};
/* *INDENT-ON* */

static clib_error_t *
cdb_unset_field_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *field = 0, *value = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%s %s", &field, &value))
    ;
  else if (unformat (line_input, "%s", &field))
    ;
  else
    {
      error = clib_error_return (0, "parse error: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rc = vlib_cdb_unset_field (field, value);
  if (rc < 0)
    error = clib_error_return (0, "cdb: failed to set field '%s'", field);

done:
  unformat_free (line_input);
  vec_free (field);
  vec_free (value);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clib_cdb_unset_field, static) = {
  .path = "cdb unset",
  .short_help = "cdb unset <field> [<value>]",
  .function = cdb_unset_field_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
