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
#include <vlib/vlib.h>
#include <vlib/cdb/cdb.h>
#include <vppinfra/mhash.h>
#include <vppinfra/hash.h>

static void
cdb_init_object_key (vlib_cdb_class_object_key_t *k,
    u32 class_index, u8 * s)
{
  clib_memset (k, 0, sizeof (k[0]));
  k->class_index = class_index;
  k->name_hash = hash_memory (s, vec_len (s), 0);
}

static_always_inline u32
cdb_get_class_index (vlib_cdb_main_t * cm, u8 * name)
{
  uword *p = mhash_get (&cm->cdb_class_index_by_name, name);
  if (!p)
    return ~0;
  return p[0];
}

static vlib_cdb_object_t *
cdb_get_object (vlib_cdb_config_datastore_t * ds, u32 ci, u8 * obj_name)
{
  uword *p;
  vlib_cdb_class_object_key_t key = {0, };

  cdb_init_object_key (&key, ci, obj_name);

  p = hash_get_mem (ds->obj_index_by_obj_key, &key);
  if (!p)
    return 0;

  return pool_elt_at_index (ds->objs, p[0]);
}

static_always_inline int
cdb_create_object (vlib_cdb_config_datastore_t *ds, u32 ci, u8 * name,
    vlib_cdb_object_action_t action)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_object_t *o;
  vlib_cdb_class_object_key_t * key;

  pool_get_zero (ds->objs, o);
  o->class_index = ci;
  o->name = vec_dup (name);
  o->action = action;

  key = clib_mem_alloc (sizeof (key[0]));
  cdb_init_object_key (key, ci, name);
  hash_set_mem (ds->obj_index_by_obj_key, key, o - ds->objs);
  cm->current_cds_obj_index = o - ds->objs;
  return 0;
}

static_always_inline void
cdb_free_value (void * v, vlib_cdb_class_item_t * item)
{
  if (!v)
    return;

  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_type_t *t = vec_elt_at_index (cm->types, item->type_index);

  if (t->is_pointer_type)
    vec_free (((void **)v)[0]);

  clib_mem_free (v);
}

static_always_inline int
cdb_delete_object (vlib_cdb_config_datastore_t * ds, vlib_cdb_object_t * o)
{
  hash_pair_t *hp;
  void *key_copy;
  vlib_cdb_class_object_key_t key;
  u32 i;

  cdb_init_object_key (&key, o->class_index, o->name);
  hp = hash_get_pair (ds->obj_index_by_obj_key, &key);
  key_copy = (void *) (hp->key);
  hash_unset_mem (ds->obj_index_by_obj_key, &key);
  clib_mem_free (key_copy);
  vlib_cdb_object_field_t *of, *ofs;

  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_class_t *c = vec_elt_at_index (cm->classes, o->class_index);

  vec_foreach_index (i, o->values)
  {
    ofs = vec_elt (o->values, i);
    vec_foreach (of, ofs)
    {
      if (!of->value)
        continue;

      vlib_cdb_class_item_t *item = vec_elt_at_index (c->items, i);
      cdb_free_value (of->value, item);
    }
    vec_free (ofs);
  }

  vec_free (o->values);
  vec_free (o->name);
  pool_put (ds->objs, o);
  return 0;
}

static_always_inline int
cdb_edit_or_delete_object (vlib_cdb_config_datastore_t *ds, u32 ci,
    vlib_cdb_object_t *co, u8 * name, vlib_cdb_object_action_t action)
{
  vlib_cdb_main_t *cm = &cdb_main;

  if (action == CDB_OBJECT_ACTION_EDIT)
    {
      if (co)
        cm->current_cds_obj_index = co - ds->objs;
      else
        cdb_create_object (ds, ci, name, action);
    }
  else if (action == CDB_OBJECT_ACTION_DELETE)
    {
      if (co)
        cdb_delete_object (ds, co);
      else
        cdb_create_object (ds, ci, name, action);
      cm->current_cds_obj_index = ~0;
    }

  return 0;
}

static_always_inline int
vlib_cdb_modify_class_object_internal (u8 * cls_name, u8 * obj_name,
        vlib_cdb_object_action_t action)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *cds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_config_datastore_t *rds = vlib_cdb_get_running_ds ();
  vlib_cdb_object_t *co, *ro;
  int rc = 0;

  if (!cls_name || !obj_name)
      return -1;

  u32 ci = cdb_get_class_index (cm, cls_name);
  if (~0 == ci)
    return -1;

  co = cdb_get_object (cds, ci, obj_name);
  ro = cdb_get_object (rds, ci, obj_name);

  switch (action)
  {
  case CDB_OBJECT_ACTION_CREATE:
    /* object must not exist anywhere */
    if (co || ro)
      return -1;
    rc = cdb_create_object (cds, ci, obj_name, action);
    break;
  case CDB_OBJECT_ACTION_EDIT:
  case CDB_OBJECT_ACTION_DELETE:
    /* object must exist at least in one data store */
    if (!co && !ro)
      return -1;
    rc = cdb_edit_or_delete_object (cds, ci, co, obj_name, action);
    break;
  }

  return rc;
}

int
vlib_cdb_create_class_object (u8 * cls_name, u8 * obj_name)
{
  return vlib_cdb_modify_class_object_internal (cls_name, obj_name,
      CDB_OBJECT_ACTION_CREATE);
}

int
vlib_cdb_edit_class_object (u8 * cls_name, u8 * obj_name)
{
  return vlib_cdb_modify_class_object_internal (cls_name, obj_name,
      CDB_OBJECT_ACTION_EDIT);
}

int
vlib_cdb_delete_class_object (u8 * cls_name, u8 * obj_name)
{
  return vlib_cdb_modify_class_object_internal (cls_name, obj_name,
      CDB_OBJECT_ACTION_DELETE);
}

static int
cdb_unformat_field_value (u8 * value, vlib_cdb_object_field_t *f,
    vlib_cdb_class_item_t * ci)
{
  int rc = 1;
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_type_t *td = vec_elt_at_index (cm->types, ci->type_index);
  f->value = clib_mem_alloc (td->size);

  unformat_input_t input;
  unformat_init_vector (&input, vec_dup (value));

  if (!unformat (&input, "%U", td->unformat, f->value))
    {
      cdb_free_value (f->value, ci);
      rc = 0;
    }

  unformat_free (&input);
  return rc;
}

static vlib_cdb_object_field_t *
cdb_get_field_by_value (vlib_cdb_object_field_t *ofs, void *v,
    vlib_cdb_class_item_t *ci)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_type_t *td = vec_elt_at_index (cm->types, ci->type_index);
  vlib_cdb_object_field_t *of;

  vec_foreach (of, ofs)
  {
    if (!td->compare (v, of->value))
      return of;
  }
  return 0;
}

int
vlib_cdb_set_field_value (u8 *field, u8 *value)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *ds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_object_t *o;
  uword *p;
  vlib_cdb_class_t *c;
  vlib_cdb_class_item_t *ci;
  int rc = 0;

  if (cm->current_cds_obj_index == ~0)
    return -1;

  o = pool_elt_at_index (ds->objs, cm->current_cds_obj_index);
  c = vec_elt_at_index (cm->classes, o->class_index);

  p = mhash_get (&c->item_index_by_name, field);
  if (!p)
    return -1;

  ci = vec_elt_at_index (c->items, p[0]);
  u32 iindex = ci->index;

  vlib_cdb_object_field_t new;
  if (!cdb_unformat_field_value (value, &new, ci))
    return -1;

  new.action = CDB_FIELD_ACTION_SET;

  vec_validate (o->values, iindex);
  vlib_cdb_object_field_t **ofs = vec_elt_at_index (o->values, iindex);

  vlib_cdb_object_field_t *of;
  if (!ofs[0])
    {
      vec_add1 (ofs[0], new);
    }
  else
    {
      if (ci->flags & CDB_CLASS_ITEM_IS_MULTIPLE)
      {
        of = cdb_get_field_by_value (ofs[0], value, ci);
        if (of) /* value already present in config datastore */
          cdb_free_value (new.value, ci);
        else
          vec_add1 (ofs[0], new);
      }
      else
      {
        of = ofs[0];
        cdb_free_value (of->value, ci);
        of[0] = new;
      }
    }

  return rc;
}

static_always_inline vlib_cdb_object_field_t *
cdb_get_field (vlib_cdb_object_t *o, u32 index, u8 * v, vlib_cdb_type_t *t,
    int val_is_formatted)
{
  vlib_cdb_object_field_t *ret = 0;
  if (!o)
    return 0;

  if (index >= vec_len (o->values))
    return 0;

  vlib_cdb_object_field_t *field, *fields = vec_elt (o->values, index);
  if (!fields)
    return 0;

  if (v)
  {
    /* convert v to cdb format */
    unformat_input_t input;
    unformat_init_vector (&input, vec_dup (v));
    void *tmp = clib_mem_alloc (t->size);

    if (!val_is_formatted && !unformat (&input, "%U", t->unformat, tmp))
      ;
    else
    {

      vec_foreach (field, fields)
      {
        if (!t->compare (val_is_formatted ? v : tmp, field->value))
        {
          ret = field;
          break;
        }
      }

    clib_mem_free (tmp);
    unformat_free (&input);
    }
  }
  else
  {
    ret = fields;
  }

  return ret;
}

static int
cdb_create_field (vlib_cdb_object_t *o, u32 index,
    void * v, vlib_cdb_field_action_t action)
{
  vec_validate (o->values, index);
  vlib_cdb_object_field_t *new = 0, **of = vec_elt_at_index (o->values, index);

  vec_add2 (of[0], new, 1);
  clib_memset (new, 0, sizeof (new[0]));
  new->action = action;
  new->value = v;
  return 0;
}

static void
cdb_delete_field (vlib_cdb_object_t *o, vlib_cdb_object_field_t *f,
    vlib_cdb_class_item_t *ci, u32 index)
{
  vlib_cdb_object_field_t *fields = vec_elt (o->values, index);
  cdb_free_value (f->value, ci);
  vec_del1 (fields, f - fields);
}

int
vlib_cdb_unset_field (u8 * field, u8 * value)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *cds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_config_datastore_t *rds = vlib_cdb_get_running_ds ();
  vlib_cdb_object_t *co, *ro;
  vlib_cdb_class_item_t *ci;
  uword *p;
  vlib_cdb_class_t *c;

  if (cm->current_cds_obj_index == ~0)
    return -1;

  co = pool_elt_at_index (cds->objs, cm->current_cds_obj_index);
  c = vec_elt_at_index (cm->classes, co->class_index);
  p = mhash_get (&c->item_index_by_name, field);
  if (!p)
    return -1;

  u32 index = p[0];
  ci = vec_elt_at_index (c->items, index);

  ro = cdb_get_object (rds, co->class_index, co->name);

  if (!(ci->flags & CDB_CLASS_ITEM_IS_MULTIPLE))
    value = 0;

  vlib_cdb_type_t *t = vec_elt_at_index (cm->types, ci->type_index);
  vlib_cdb_object_field_t * rf = cdb_get_field (ro, index, value, t, 0);
  vlib_cdb_object_field_t * cf = cdb_get_field (co, index, value, t, 0);

  if (rf) /* field exists in running config */
    {
      if (cf)
        cf->action = CDB_FIELD_ACTION_UNSET;
      else
      {
        void *val = clib_mem_alloc(t->size);
        clib_memcpy (val, rf->value, t->size);
        cdb_create_field (co, index, val, CDB_FIELD_ACTION_UNSET);
      }
    }
  else
  {
    if (cf)
      cdb_delete_field (co, cf, ci, index);
  }

  return 0;
}

static void
cdb_free_object (vlib_cdb_main_t *cm, vlib_cdb_object_t *o)
{
  u32 i;
  vlib_cdb_object_field_t *ofs, *of;
  vlib_cdb_class_t *c = vec_elt_at_index (cm->classes, o->class_index);
  vlib_cdb_class_item_t *ci;

  vec_foreach_index (i, o->values)
  {
    ofs = vec_elt (o->values, i);
    ci = vec_elt_at_index (c->items, i);

    vec_foreach (of, ofs)
    {
      cdb_free_value (of->value, ci);
    }
    vec_free (ofs);
  }
}

static int
cdb_clear_config (vlib_cdb_main_t *cm,
    vlib_cdb_config_datastore_t *ds)
{
  hash_pair_t *hp;
  vlib_cdb_object_t *o;

  cm->current_cds_obj_index = ~0;

  /* *INDENT-OFF* */
  pool_foreach (o, ds->objs,
  ({
    cdb_free_object (cm, o);
   }));

  hash_foreach_pair (hp, ds->obj_index_by_obj_key,
  ({
    clib_mem_free ((void *)hp->key);
   }));
  /* *INDENT-ON* */

  hash_free (ds->obj_index_by_obj_key);
  ds->obj_index_by_obj_key =
    hash_create_mem (0, sizeof (vlib_cdb_class_object_key_t), sizeof (uword));
  pool_free (ds->objs);
  ds->objs = 0;

  return 0;
}

int
vlib_cdb_clear_candidate_config (void)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *cds = vlib_cdb_get_candidate_ds ();
  return cdb_clear_config (cm, cds);
}

static clib_error_t *
cdb_call_hooks_on_items (vlib_cdb_class_t * c, vlib_cdb_object_t *o,
    u8 is_verify)
{
  clib_error_t * error = 0;
  u32 i;
  vlib_cdb_object_field_t *ofs, *of;
  vlib_cdb_verify_item_callback_t *icb;

  vec_foreach_index (i, o->values)
  {
    ofs = vec_elt (o->values, i);
    if (!ofs)
      continue;

    vec_foreach (of, ofs)
    {
    vlib_cdb_class_item_t *ci = vec_elt_at_index (c->items, i);
    vec_foreach (icb, c->icbs)
      {
        if (*icb)
          error = (*icb) (c->name, o, ci, of->value, of->action, is_verify);

        if (error)
          return error;
      }
    }
  }
  return 0;
}

static clib_error_t *
cdb_call_hooks_on_object (vlib_cdb_config_datastore_t *ds,
    vlib_cdb_object_t * o, vlib_cdb_class_t *c, u8 is_verify)
{
  clib_error_t * error = 0;
  vlib_cdb_verify_object_callback_t *ocb;
  vlib_cdb_verify_item_callback_t *icb;

  vec_foreach (ocb, c->ocbs)
    {
      if (*ocb)
        {
          error = (*ocb) (c->name, o, o->action, is_verify);

          if (is_verify)
            {
              if (error)
                return error;
            }
          else
            {
              /* this is a notification, ignore any error thrown */
              if (error)
                clib_error_free (error);
            }
        }
    }

  vec_foreach (icb, c->icbs)
  {
    error = cdb_call_hooks_on_items (c, o, is_verify);
    if (error)
      return error;
  }

  return 0;
}

static clib_error_t *
cdb_call_hooks (vlib_cdb_config_datastore_t *ds, u8 is_verify)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_object_t *o;
  vlib_cdb_class_t *c;
  clib_error_t * error = 0;

  /* *INDENT-OFF* */
  pool_foreach (o, ds->objs,
  ({
    c = vec_elt_at_index (cm->classes, o->class_index);
    error = cdb_call_hooks_on_object (ds, o, c, is_verify);
    if (error)
      return error;
  }));
  /* *INDENT-ON* */

  return 0;
}

static void *
cdb_copy_value (void * v, vlib_cdb_type_t *t)
{
  void *new = clib_mem_alloc (t->size);
  if (t->is_pointer_type)
    new = vec_dup (*((void **)v)); // TODO only vectors are supported
  else
    clib_memcpy (new, v, t->size);

  return new;
}

static int
cdb_update_field (vlib_cdb_main_t * cm,
    vlib_cdb_object_t *ro,
    vlib_cdb_object_field_t *cof,
    vlib_cdb_class_item_t *ci,
    u32 index)
{
  vlib_cdb_type_t *t = vec_elt_at_index (cm->types, ci->type_index);
  vlib_cdb_object_field_t *rof = 0;

  if (ci->flags & CDB_CLASS_ITEM_IS_MULTIPLE)
    rof = cdb_get_field (ro, index, cof->value, t, 1);
  else
    if (ro->values && index < vec_len(ro->values))
      rof = vec_elt (ro->values, index);

  if (rof)
    cdb_delete_field (ro, rof, ci, index);

  if (cof->action == CDB_FIELD_ACTION_SET)
    {
      void *copy_v = cdb_copy_value (cof->value, t);
      cdb_create_field (ro, index, copy_v, CDB_FIELD_ACTION_SET);
    }

  return 0;
}

static int
cdb_update_object (vlib_cdb_main_t *cm,
    vlib_cdb_object_t * co, vlib_cdb_config_datastore_t * rds)
{
  u32 i;
  vlib_cdb_object_t *ro;
  vlib_cdb_class_t *c = vec_elt_at_index (cm->classes, co->class_index);

  ro = cdb_get_object (rds, co->class_index, co->name);

  if (co->action == CDB_OBJECT_ACTION_DELETE)
  {
    if (!ro)
      return 0;

    return cdb_edit_or_delete_object (rds, ro->class_index, ro, 0,
        CDB_OBJECT_ACTION_DELETE);
  }

  if (co->action == CDB_OBJECT_ACTION_CREATE)
    {
      if (!ro)
        cdb_create_object (rds, co->class_index, co->name, 0 /* unused */);

      /* re-fetch object pointer */
      ro = cdb_get_object (rds, co->class_index, co->name);
    }
  ASSERT (ro);

  vec_foreach_index (i, co->values)
  {
    vlib_cdb_object_field_t *cof, *cofs = vec_elt (co->values, i);
    vec_foreach (cof, cofs)
    {
      if (!cof->value && cof->action != CDB_FIELD_ACTION_UNSET)
        continue;

      vlib_cdb_class_item_t *ci = vec_elt_at_index (c->items, i);
      cdb_update_field (cm, ro, cof, ci, i);
    }
  }
  return 0;
}

static int
cdb_commit_internal (vlib_cdb_main_t *cm,
        vlib_cdb_config_datastore_t * cds,
        vlib_cdb_config_datastore_t * rds)
{
  vlib_cdb_object_t *co;

  /* *INDENT-OFF* */
  pool_foreach (co, cds->objs,
  ({
    cdb_update_object (cm, co, rds);
  }));
  /* *INDENT-ON* */

  return 0;
}

int
vlib_cdb_commit (void)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *cds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_config_datastore_t *rds = vlib_cdb_get_running_ds ();
  clib_error_t * error;

  error = cdb_call_hooks (cds, 1 /* is_verify */);
  if (error)
    {
      vlib_cli_output (vm, "commit failed: %U\n", format_clib_error, error);
      clib_error_free (error);
      return -1;
    }

  cdb_commit_internal (cm, cds, rds);
  cdb_call_hooks (cds, 0 /* is_verify */);
  cdb_clear_config (cm, cds);
  return 0;
}

int
vlib_cdb_register_commit_cb (char * class,
    vlib_cdb_verify_object_callback_t ocb,
    vlib_cdb_verify_item_callback_t icb)
{
  vlib_cdb_main_t *cm = &cdb_main;
  uword * p;
  vlib_cdb_class_t * c;

  p = mhash_get (&cm->cdb_class_index_by_name, class);
  if (!p)
    return -1;

  c = vec_elt_at_index (cm->classes, p[0]);

  if (ocb)
    vec_add1 (c->ocbs, ocb);
  if (icb)
    vec_add1 (c->icbs, icb);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
