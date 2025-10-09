/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ptclosure.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/lookup/parser.h>

static sfdp_service_registration_t **
sfdp_service_init_for_scope (vlib_main_t *vm,
			     sfdp_service_registration_t **services,
			     uword *index_reg_by_name,
			     uword **service_index_by_name)
{
  sfdp_service_registration_t *current_reg;
  sfdp_service_registration_t **res_services = 0;
  u8 **runs_after_table = 0;
  u8 **closure = 0;
  uword *ordered_indices = 0;
  uword current_index = vec_len (services);

  /* Build the constraints matrix */
  if (current_index == 0)
    return res_services;
  current_reg = services[0];
  runs_after_table = clib_ptclosure_alloc (current_index);

  while (current_index > 0)
    {
      char **current_target;
      current_index--;
      current_reg = vec_elt_at_index (services, current_index)[0];

      /* Process runs_before and runs_after constraints */
      current_target = current_reg->runs_before;
      while (current_target[0])
	{
	  uword *res = hash_get_mem (index_reg_by_name, current_target[0]);
	  if (res)
	    runs_after_table[res[0]][current_index] = 1;
	  current_target++;
	}
      current_target = current_reg->runs_after;
      while (current_target[0])
	{
	  uword *res = hash_get_mem (index_reg_by_name, current_target[0]);
	  if (res)
	    runs_after_table[current_index][res[0]] = 1;
	  current_target++;
	}
    }
  /*hash_free (index_reg_by_name);*/
  closure = clib_ptclosure (runs_after_table);
again:
  for (int i = 0; i < vec_len (services); i++)
    {
      for (int j = 0; j < vec_len (services); j++)
	{
	  if (closure[i][j])
	    {
	      /* i runs after j so it can't be output */
	      goto skip_i;
	    }
	}
      /* i doesn't run after any pending element so it can be output */
      vec_add1 (ordered_indices, i);
      for (int j = 0; j < vec_len (services); j++)
	closure[j][i] = 0;
      closure[i][i] = 1;
      goto again;
    skip_i:;
    }
  if (vec_len (services) != vec_len (ordered_indices))
    clib_panic ("Failed to build total order for sfdp services");
  clib_ptclosure_free (runs_after_table);
  clib_ptclosure_free (closure);

  vec_resize (res_services, vec_len (services));
  for (uword i = 0; i < vec_len (ordered_indices); i++)
    {
      current_reg = vec_elt_at_index (services, ordered_indices[i])[0];
      *current_reg->index_in_bitmap = i;
      *current_reg->service_mask = 1ULL << i;
      res_services[i] = current_reg;
      hash_set_mem (*service_index_by_name, current_reg->node_name, i);
    }
  /*sm->service_index_by_name = service_index_by_name;*/
  /*vec_free (services);*/
  vec_free (ordered_indices);

  /* Build the graph */
  services = res_services;
  for (uword i = 0; i < vec_len (services); i++)
    {
      sfdp_service_registration_t *reg_i = vec_elt_at_index (services, i)[0];
      vlib_node_t *node_i =
	vlib_get_node_by_name (vm, (u8 *) reg_i->node_name);
      if (node_i == 0)
	continue;
      if (reg_i->is_terminal)
	continue;
      sfdp_service_next_indices_init (vm, node_i->index, services);
    }
  return res_services;
}

static void
sfdp_service_init_parser_node_for_scope (
  vlib_main_t *vm, vlib_node_registration_t *original_reg,
  sfdp_service_registration_t **services, u32 scope_index,
  const char *scope_name)
{
  sfdp_main_t *sfdp = &sfdp_main;
  uword *parser_node_index_per_scope;
  vlib_node_registration_t r;
  sfdp_lookup_node_runtime_data_t rt = { .scope_index = scope_index };

  uword original_node_index;
  uword node_index;

  original_node_index = original_reg->index;
  vec_validate (sfdp->parser_node_index_per_scope_per_original,
		original_node_index);
  parser_node_index_per_scope = vec_elt_at_index (
    sfdp->parser_node_index_per_scope_per_original, original_node_index)[0];
  vec_validate (parser_node_index_per_scope, scope_index);
  if (scope_index != 0)
    {
      clib_memset (&r, 0, sizeof (r));
      r.vector_size = sizeof (u32);
      r.format_trace = original_reg->format_trace;
      r.type = VLIB_NODE_TYPE_INTERNAL;
      r.runtime_data = &rt;
      r.runtime_data_bytes = sizeof (rt);
      r.n_errors = original_reg->n_errors;
      r.error_strings = original_reg->error_strings;
      r.error_counters = original_reg->error_counters;
      r.node_fn_registrations = original_reg->node_fn_registrations;
      r.flags = original_reg->flags;
      node_index =
	vlib_register_node (vm, &r, "%s-%s", original_reg->name, scope_name);
    }
  else
    node_index = original_node_index;

  parser_node_index_per_scope[scope_index] = node_index;
  sfdp->parser_node_index_per_scope_per_original[original_node_index] =
    parser_node_index_per_scope;
  sfdp_service_next_indices_init (vm, node_index, services);
}

static void
sfdp_service_init_nodes_for_scope (vlib_main_t *vm, u32 scope_index)
{
  sfdp_service_main_t *sm = &sfdp_service_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_parser_main_t *pm = &sfdp_parser_main;

  const char *scope_name = vec_elt_at_index (sm->scope_names, scope_index)[0];
  vlib_node_registration_t r;
  sfdp_service_registration_t **services =
    vec_elt_at_index (sm->services_per_scope_index, scope_index)[0];
  uword node_index;
  sfdp_lookup_node_runtime_data_t rt = { .scope_index = scope_index };
  sfdp_parser_registration_mutable_t *preg = pm->regs;

#define _(n, s, x)                                                            \
  if (scope_index != 0)                                                       \
    {                                                                         \
      clib_memset (&r, 0, sizeof (r));                                        \
      r.vector_size = sizeof (u32);                                           \
      r.format_trace = (n).format_trace;                                      \
      r.type = VLIB_NODE_TYPE_INTERNAL;                                       \
      r.runtime_data = &rt;                                                   \
      r.runtime_data_bytes = sizeof (rt);                                     \
      r.n_errors = (n).n_errors;                                              \
      r.error_strings = (n).error_strings;                                    \
      r.error_counters = (n).error_counters;                                  \
      r.node_fn_registrations = (n).node_fn_registrations;                    \
      r.flags = (n).flags;                                                    \
      node_index = vlib_register_node (vm, &r, s "-%s", scope_name);          \
      vec_validate (sfdp->x##_node_index_per_scope, scope_index);             \
      sfdp->x##_node_index_per_scope[scope_index] = node_index;               \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      node_index = (n).index;                                                 \
      vec_validate (sfdp->x##_node_index_per_scope, scope_index);             \
      sfdp->x##_node_index_per_scope[scope_index] = node_index;               \
    }                                                                         \
                                                                              \
  sfdp_service_next_indices_init (vm, node_index, services);

  _ (sfdp_lookup_ip4_node, "sfdp-lookup-ip4", ip4_lookup)
  _ (sfdp_lookup_ip6_node, "sfdp-lookup-ip6", ip6_lookup)
  _ (sfdp_handoff_node, "sfdp-handoff", handoff)
#undef _
  vec_validate (sfdp->frame_queue_index_per_scope, scope_index);

  /* Last node index is handoff node */
  sfdp->frame_queue_index_per_scope[scope_index] =
    vlib_frame_queue_main_init (node_index, 0);

  /* Same work for all parser nodes */
  while (preg)
    {
      if (preg->node_reg)
	sfdp_service_init_parser_node_for_scope (vm, preg->node_reg, services,
						 scope_index, scope_name);
      preg = preg->next;
    }
}

static clib_error_t *
sfdp_service_init (vlib_main_t *vm)
{
  sfdp_service_main_t *sm = &sfdp_service_main;
  sfdp_service_registration_t ***services_per_scope_index = 0;
  sfdp_service_registration_t *current_reg;
  uword *index_reg_by_name = hash_create_string (0, sizeof (uword));
  uword *service_index_by_name = hash_create_string (0, sizeof (uword));
  uword *scope_index_by_name = hash_create_string (0, sizeof (uword));
  u32 n_scopes = 1;
  const char **scope_names = 0;

  vec_validate (services_per_scope_index, 0);
  vec_validate (scope_names, 0);
  scope_names[0] = "default";

  current_reg = sm->next_service;

  vlib_call_init_function (vm, sfdp_parser_init);
  /* Parse the registrations linked list */
  while (current_reg)
    {
      sfdp_service_registration_t **services;
      uword *si;
      u32 scope_index;
      const char *name = current_reg->node_name;
      const char *scope = current_reg->scope;
      uword *res = hash_get_mem (index_reg_by_name, name);
      uword current_index;

      if (res)
	clib_panic ("Trying to register %s twice!", name);

      /* Scope already exists ? */
      if (scope == 0)
	scope_index = 0;
      else if ((si = hash_get_mem (scope_index_by_name, scope)) == 0)
	{
	  /* Create scope */
	  scope_index = n_scopes;
	  n_scopes += 1;
	  hash_set_mem (scope_index_by_name, scope, scope_index);
	  vec_validate (scope_names, scope_index);
	  scope_names[scope_index] = scope;
	}
      else
	scope_index = *si;

      vec_validate (services_per_scope_index, scope_index);

      services = *vec_elt_at_index (services_per_scope_index, scope_index);
      current_index = vec_len (services);
      vec_add1 (services, current_reg);
      services_per_scope_index[scope_index] = services;
      hash_set_mem (index_reg_by_name, name, current_index);
      current_reg = current_reg->next;
    }

  /* Initialise each scope */
  for (int i = 0; i < n_scopes; i++)
    {
      sfdp_service_registration_t **res_services;
      res_services = sfdp_service_init_for_scope (
	vm, services_per_scope_index[i], index_reg_by_name,
	&service_index_by_name);
      vec_free (services_per_scope_index[i]);
      services_per_scope_index[i] = res_services;
    }
  sm->scope_names = scope_names;
  sm->scope_index_by_name = scope_index_by_name;
  sm->n_scopes = n_scopes;
  sm->service_index_by_name = service_index_by_name;
  sm->services_per_scope_index = services_per_scope_index;
  hash_free (index_reg_by_name);

  /* Create the lookup nodes for each scope */
  for (int i = 0; i < n_scopes; i++)
    sfdp_service_init_nodes_for_scope (vm, i);

  /* Connect lookup nodes to handoff nodes of other scopes */
  for (int i = 0; i < n_scopes; i++)
    for (int j = 0; j < n_scopes; j++)
      {
	uword from_ni_v4, from_ni_v6, from_ni_hoff, from_ni_parser, to_ni;
	uword **parser_node_index_per_scope;
	from_ni_v4 = sfdp_main.ip4_lookup_node_index_per_scope[i];
	from_ni_v6 = sfdp_main.ip6_lookup_node_index_per_scope[i];
	from_ni_hoff = sfdp_main.handoff_node_index_per_scope[i];
	to_ni = sfdp_main.handoff_node_index_per_scope[j];

	if (i == j)
	  continue;
	vlib_node_add_next_with_slot (vm, from_ni_v4, to_ni,
				      SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE (j));
	vlib_node_add_next_with_slot (vm, from_ni_v6, to_ni,
				      SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE (j));
	vlib_node_add_next_with_slot (vm, from_ni_hoff, to_ni,
				      SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE (j));

	/* Connect each parser_node for scope i to handoff of scope j */
	vec_foreach (parser_node_index_per_scope,
		     sfdp_main.parser_node_index_per_scope_per_original)
	  if (vec_len (parser_node_index_per_scope) > i)
	    {
	      from_ni_parser = parser_node_index_per_scope[0][i];
	      vlib_node_add_next_with_slot (
		vm, from_ni_parser, to_ni,
		SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE (j));
	    }
      }

  vlib_node_main_lazy_next_update (vm);
  return 0;
}

void
sfdp_service_next_indices_init (vlib_main_t *vm, uword node_index,
				sfdp_service_registration_t **services)
{
  for (uword i = 0; i < vec_len (services); i++)
    {
      sfdp_service_registration_t *reg = vec_elt_at_index (services, i)[0];
      vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) reg->node_name);
      if (node)
	vlib_node_add_next_with_slot (vm, node_index, node->index,
				      *reg->index_in_bitmap);
    }
}

VLIB_INIT_FUNCTION (sfdp_service_init);
sfdp_service_main_t sfdp_service_main;