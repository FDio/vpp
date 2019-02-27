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

vlib_cdb_main_t cdb_main;

/* *INDENT-OFF* */
VLIB_REGISTER_CDB_CLASS (interface) = {
  .name = "interface",
};

VLIB_REGISTER_CDB_CLASS_ITEM (interface_admin_state) = {
  .class = "interface",
  .name = "admin-state",
  .type = "interface-state",
  .description = "interface admin state",
};

VLIB_REGISTER_CDB_CLASS_ITEM (interface_desc) = {
  .class = "interface",
  .name = "description",
  .type = "string",
  .description = "description",
};

VLIB_REGISTER_CDB_CLASS_ITEM (interface_mtu) = {
  .class = "interface",
  .name = "mtu",
  .type = "u32",
  .description = "MTU",
};

VLIB_REGISTER_CDB_CLASS_ITEM (interface_mac) = {
  .class = "interface",
  .name = "mac-address",
  .type = "mac-addr",
  .description = "MAC address",
};
/* *INDENT-ON* */

static void
vlib_cdb_init_ds (vlib_cdb_config_datastore_t * ds)
{
  ds->obj_index_by_obj_key =
    hash_create_mem (0, sizeof (vlib_cdb_class_object_key_t), sizeof (uword));
  ds->objs = 0;
}

static clib_error_t *
vlib_cdb_init (vlib_main_t * vm)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_type_registration_t *tr = cm->type_registrations;
  vlib_cdb_class_registration_t *cr = cm->class_registrations;
  vlib_cdb_class_item_registration_t *ir = cm->class_item_registrations;

  mhash_init_c_string (&cm->cdb_type_index_by_name, sizeof (uword));
  mhash_init_c_string (&cm->cdb_class_index_by_name, sizeof (uword));

  vlib_cdb_init_ds (&cm->candidate);
  vlib_cdb_init_ds (&cm->running);
  cm->current_cds_obj_index = ~0;

  while (tr)
    {
      vlib_cdb_type_t *t;
      clib_warning ("type: %s", tr->name);
      if (mhash_get (&cm->cdb_type_index_by_name, tr->name))
	return clib_error_return (0, "Duplicate CDB type '%s'", tr->name);

      vec_add2 (cm->types, t, 1);
      t->index = t - cm->types;
      t->name = tr->name;
      t->size = tr->size;
      t->is_pointer_type = tr->is_pointer_type;
      t->compare = tr->compare;

      if (!tr->unformat || !tr->format)
        {
          return clib_error_return (0, "formating function(s) missing for "
              "cdb type '%s'!", t->name);
        }

      t->unformat = tr->unformat;
      t->format = tr->format;
      mhash_set (&cm->cdb_type_index_by_name, tr->name, t->index, 0);

      /* next */
      tr = tr->next;
    }

  while (cr)
    {
      vlib_cdb_class_t *c;
      clib_warning ("class: %s", cr->name);
      if (mhash_get (&cm->cdb_class_index_by_name, cr->name))
	return clib_error_return (0, "Duplicate CDB class '%s'", cr->name);

      vec_add2 (cm->classes, c, 1);
      c->index = c - cm->classes;
      c->name = cr->name;
      mhash_init_c_string (&c->item_index_by_name, sizeof (uword));

      mhash_set (&cm->cdb_class_index_by_name, cr->name, c->index, 0);

      /* next */
      cr = cr->next;
    }

  while (ir)
    {
      vlib_cdb_class_t *c;
      vlib_cdb_class_item_t *i;
      uword *p;
      p = mhash_get (&cm->cdb_class_index_by_name, ir->class);

      if (p == 0)
	return clib_error_return (0, "Unknown CDB class '%s'", ir->class);

      c = vec_elt_at_index (cm->classes, p[0]);

      if (mhash_get (&c->item_index_by_name, ir->name))
	return clib_error_return (0, "Duplicate item '%s' in CDB class '%s'",
				  ir->name, c->name);

      p = mhash_get (&cm->cdb_type_index_by_name, ir->type);

      if (p == 0)
	return clib_error_return (0, "Unknown CDB type '%s'", ir->type);

      clib_warning ("adding item '%s' of type '%s' to class '%s'",
		    ir->name, ir->type, c->name);
      vec_add2 (c->items, i, 1);
      i->index = i - c->items;
      i->type_index = p[0];
      i->name = ir->name;
      i->description = ir->description;
      i->flags = ir->flags;

      mhash_set (&c->item_index_by_name, ir->name, i->index, 0);

      /* next */
      ir = ir->next;
    }
  return 0;
}

VLIB_INIT_FUNCTION (vlib_cdb_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
