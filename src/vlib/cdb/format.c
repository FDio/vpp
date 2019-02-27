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

#include <vlib/cdb/format.h>

u8 *
format_cdb_object_action (u8 * s, va_list * va)
{
  vlib_cdb_object_action_t a = va_arg (*va, vlib_cdb_object_action_t);
  char * v = "??";

  switch (a)
  {
  case CDB_OBJECT_ACTION_CREATE:
    v = "create";
    break;
  case CDB_OBJECT_ACTION_EDIT:
    v = "edit";
    break;
  case CDB_OBJECT_ACTION_DELETE:
    v = "delete";
    break;
  }
  return format (s, "%s", v);
}

u8 *
format_cdb_field_action (u8 * s, va_list * va)
{
  vlib_cdb_field_action_t a = va_arg (*va, vlib_cdb_field_action_t);
  char *a_str = "??";

  switch (a)
  {
    case CDB_FIELD_ACTION_SET:
      a_str = "set";
      break;
    case CDB_FIELD_ACTION_UNSET:
      a_str = "unset";
      break;
    default:
      break;
  }

  return format (s, "%s", a_str);
}

u8 *
format_cdb_object_field (u8 * s, va_list * va)
{
  vlib_cdb_type_t *t = va_arg (*va, vlib_cdb_type_t *);
  vlib_cdb_class_item_t *ci = va_arg (*va, vlib_cdb_class_item_t *);
  vlib_cdb_object_field_t *v = va_arg (*va, vlib_cdb_object_field_t *);
  int is_candidate = va_arg (*va, int);

  if (is_candidate)
    s = format (s, "  %U", format_cdb_field_action, v->action);

  s = format (s, "  %s", ci->name);

  if (v->value)
    s = format (s, " %U", t->format, v->value);

  s = format (s, "\n");

  return s;
}

u8 *
format_cdb_object (u8 * s, va_list * va)
{
  vlib_cdb_object_t *o = va_arg (*va, vlib_cdb_object_t *);
  int is_candidate =  va_arg (*va, int);

  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_type_t *t;
  vlib_cdb_class_item_t *item_desc;
  u32 i;
  vlib_cdb_object_field_t *of, *ofs;

  vlib_cdb_class_t *c = cm->classes + o->class_index;

  if (is_candidate)
    s = format (s, "%U ", format_cdb_object_action, o->action);

  s = format (s, "%s %v\n", c->name, o->name);

  vec_foreach_index (i, o->values)
  {
    ofs = vec_elt (o->values, i);
    vec_foreach (of, ofs)
    {
      if (!of->value && of->action != CDB_FIELD_ACTION_UNSET)
        continue;

      item_desc = c->items + i;
      t = cm->types + item_desc->type_index;
      s = format (s, "%U", format_cdb_object_field, t, item_desc, of,
          is_candidate);
    }
  }

  return s;
}

