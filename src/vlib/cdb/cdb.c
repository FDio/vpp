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
cdb_delete_value (void * v, vlib_cdb_class_item_t * item)
{
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
  vlib_cdb_object_field_t *of;

  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_class_t *c = vec_elt_at_index (cm->classes, o->class_index);

  vec_foreach_index (i, o->values)
  {
    of = vec_elt_at_index (o->values, i);
    if (!of->value)
      continue;

    vlib_cdb_class_item_t *item = vec_elt_at_index (c->items, i);
    cdb_delete_value (of->value, item);
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

int
vlib_cdb_set_field_value (u8 *field, u8 *value)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *ds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_object_t *o;
  uword *p;
  vlib_cdb_class_t *c;
  vlib_cdb_class_item_t *item_desc;
  int rc = 0;
  void *old_val = 0;
  vlib_cdb_type_t *td;

  if (cm->current_cds_obj_index == ~0)
    return -1;

  o = pool_elt_at_index (ds->objs, cm->current_cds_obj_index);
  c = vec_elt_at_index (cm->classes, o->class_index);

  p = mhash_get (&c->item_index_by_name, field);
  if (!p)
    return -1;

  item_desc = vec_elt_at_index (c->items, p[0]);
  u32 iindex = item_desc->index;

  vec_validate (o->values, iindex);
  vlib_cdb_object_field_t *of = vec_elt_at_index (o->values, iindex);
  if (of->value)
    {
      /* maybe replace current field value */
      old_val = of->value;
    }

  td = vec_elt_at_index (cm->types, item_desc->type_index);

  of->value = clib_mem_alloc (td->size);

  unformat_input_t input;
  unformat_init_vector (&input, vec_dup (value));

  if (!unformat (&input, "%U", td->unformat, of->value))
    {
      clib_mem_free (of->value);
      of->value = old_val;
      old_val = 0;
      rc = -1;
    }

  if (old_val)
    cdb_delete_value (old_val, item_desc);
  else
    of->action = CDB_FIELD_ACTION_SET;

  unformat_free (&input);
  return rc;
}

static_always_inline vlib_cdb_object_field_t *
cdb_get_field (vlib_cdb_object_t *o, u32 index)
{
  if (!o)
    return 0;

  if (index >= vec_len (o->values))
    return 0;

  vlib_cdb_object_field_t *ret = vec_elt_at_index (o->values, index);
  if (!ret->value)
    return 0;

  return ret;
}

static int
cdb_create_field (vlib_cdb_object_t *o, u32 index,
    void * v, vlib_cdb_field_action_t action)
{
  vec_validate (o->values, index);
  vlib_cdb_object_field_t *of = vec_elt_at_index (o->values, index);

  clib_memset (of, 0, sizeof (of[0]));
  of->action = action;
  of->value = v;
  return 0;
}

int
vlib_cdb_unset_field (u8 * field)
{
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *cds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_config_datastore_t *rds = vlib_cdb_get_running_ds ();
  vlib_cdb_object_t *co, *ro;
  vlib_cdb_class_item_t *item_desc;
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
  item_desc = vec_elt_at_index (c->items, index);

  ro = cdb_get_object (rds, co->class_index, co->name);

  vlib_cdb_object_field_t * rf = cdb_get_field (ro, index);
  vlib_cdb_object_field_t * cf = cdb_get_field (co, index);

  if (rf) /* field exists in running config */
    {
      if (cf)
        cf->action = CDB_FIELD_ACTION_UNSET;
      else
        cdb_create_field (co, index, 0, CDB_FIELD_ACTION_UNSET);
    }
  else
  {
    if (cf)
      {
        cdb_delete_value (cf->value, item_desc);
        cf->value = 0;
      }
  }

  return 0;
}

int
cdb_clear_config_internal (vlib_cdb_main_t *cm,
    vlib_cdb_config_datastore_t *ds)
{
  cm->current_cds_obj_index = ~0;
  return 0;
}

static int
cdb_call_hooks (vlib_cdb_config_datastore_t *ds, u8 is_precommit)
{
  vlib_cdb_object_t *o;

  /* *INDENT-OFF* */
  pool_foreach (o, ds->objs,
  ({
      if (is_precommit)
      {
#if 0
        if (o->precommit_fn())
        {

        }
#endif
      }
      else
      {
        // o->postcommit_fn(o);
      }
  }));
  /* *INDENT-ON* */

  return 0;
}

static int
cdb_update_field (vlib_cdb_main_t * cm,
    vlib_cdb_object_t *o,
    vlib_cdb_object_field_t *of,
    vlib_cdb_class_item_t *ci,
    u32 index)
{
  vlib_cdb_object_field_t *rof = 0;

  if (index < vec_len (o->values))
  {
    rof = vec_elt_at_index (o->values, index);
    if (!rof->value)
      rof = 0;
  }

  if (rof)
    {
      cdb_delete_value (rof->value, ci);
      rof->value = 0;
    }

  if (of->action == CDB_FIELD_ACTION_SET)
    {
      cdb_create_field (o, index, of->value, 0 /* unused */);
      of->value = 0;
    }

  return 0;
}

static int
cdb_update_object (vlib_cdb_main_t *cm,
    vlib_cdb_object_t * o, vlib_cdb_config_datastore_t * ds)
{
  u32 i;
  vlib_cdb_object_t *ro;
  vlib_cdb_class_t *c = vec_elt_at_index (cm->classes, o->class_index);

  ro = cdb_get_object (ds, o->class_index, o->name);

  if (o->action == CDB_OBJECT_ACTION_DELETE)
  {
    if (!ro)
      return 0;

    return cdb_edit_or_delete_object (ds, ro->class_index, ro, 0,
        CDB_OBJECT_ACTION_DELETE);
    // TODO notif cb
  }

  if (o->action == CDB_OBJECT_ACTION_CREATE)
  {
    if (!ro)
      cdb_create_object (ds, o->class_index, o->name, 0 /* unused */);

    /* re-fetch object pointer */
    ro = cdb_get_object (ds, o->class_index, o->name);
  }
  ASSERT (ro);

  vec_foreach_index (i, o->values)
  {
    vlib_cdb_object_field_t *of = vec_elt_at_index (o->values, i);
    if (!of->value)
      continue;

    vlib_cdb_class_item_t *ci = vec_elt_at_index (c->items, i);
    cdb_update_field (cm, ro, of, ci, i);
    // NOTIF
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
  vlib_cdb_main_t *cm = &cdb_main;
  vlib_cdb_config_datastore_t *cds = vlib_cdb_get_candidate_ds ();
  vlib_cdb_config_datastore_t *rds = vlib_cdb_get_running_ds ();

  int rc = cdb_call_hooks (cds, 1 /* is_precommit */);
  if (rc < 0)
    return rc;

  cdb_commit_internal (cm, cds, rds);
  cdb_call_hooks (cds, 0 /* is_precommit */);
  cdb_clear_config_internal (cm, cds);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
