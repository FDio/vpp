/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/feature/feature.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "feature",
  .subclass_name = "c",
};
#define log_info(f, ...)                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, dev_log.class, "%s: " fmt, __func__,         \
	    ##__VA_ARGS__)

vnet_feature_main_t feature_main;

typedef struct vnet_feature_upd_registration_t_
{
  vnet_feature_update_cb_t cb;
  void *data;
} vnet_feature_upd_registration_t;

static vnet_feature_upd_registration_t *regs;

void
vnet_feature_register (vnet_feature_update_cb_t cb, void *data)
{
  vnet_feature_upd_registration_t *reg;

  vec_add2 (regs, reg, 1);

  reg->cb = cb;
  reg->data = data;
}

static void
vnet_feature_reg_invoke (u32 sw_if_index, u8 arc_index, u8 is_enable)
{
  vnet_feature_upd_registration_t *reg;

  log_info ("registration invocation starting");
  vec_foreach (reg, regs)
    reg->cb (sw_if_index, arc_index, is_enable, reg->data);
  log_info ("registration invocation ended");
}


static clib_error_t *
vnet_feature_init (vlib_main_t * vm)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_registration_t *freg;
  vnet_feature_arc_registration_t *areg;
  vnet_feature_constraint_registration_t *creg;
  u32 arc_index = 0;

  fm->arc_index_by_name = hash_create_string (0, sizeof (uword));
  areg = fm->next_arc;

  /* process feature arc registrations */
  while (areg)
    {
      char *s;
      int i = 0;
      areg->feature_arc_index = arc_index;
      if (areg->arc_index_ptr)
	*areg->arc_index_ptr = arc_index;
      hash_set_mem (fm->arc_index_by_name, areg->arc_name,
		    pointer_to_uword (areg));

      /* process start nodes */
      while ((s = areg->start_nodes[i]))
	{
	  i++;
	}
      areg->n_start_nodes = i;

      /* next */
      areg = areg->next;
      arc_index++;
    }

  vec_validate (fm->next_feature_by_arc, arc_index - 1);
  vec_validate (fm->feature_nodes, arc_index - 1);
  vec_validate (fm->feature_config_mains, arc_index - 1);
  vec_validate (fm->next_feature_by_name, arc_index - 1);
  vec_validate (fm->sw_if_index_has_features, arc_index - 1);
  vec_validate (fm->feature_count_by_sw_if_index, arc_index - 1);
  vec_validate (fm->next_constraint_by_arc, arc_index - 1);

  freg = fm->next_feature;
  while (freg)
    {
      vnet_feature_registration_t *next;
      uword *p = hash_get_mem (fm->arc_index_by_name, freg->arc_name);
      if (p == 0)
	{
	  /* Don't start vpp with broken features arcs */
	  clib_warning ("Unknown feature arc '%s'", freg->arc_name);
	  os_exit (1);
	}

      areg = uword_to_pointer (p[0], vnet_feature_arc_registration_t *);
      arc_index = areg->feature_arc_index;

      next = freg->next;
      freg->next_in_arc = fm->next_feature_by_arc[arc_index];
      fm->next_feature_by_arc[arc_index] = freg;

      /* next */
      freg = next;
    }

  /* Move bulk constraints to the constraint by arc lists */
  creg = fm->next_constraint;
  while (creg)
    {
      vnet_feature_constraint_registration_t *next;
      uword *p = hash_get_mem (fm->arc_index_by_name, creg->arc_name);
      if (p == 0)
	{
	  /* Don't start vpp with broken features arcs */
	  clib_warning ("Unknown feature arc '%s'", creg->arc_name);
	  os_exit (1);
	}

      areg = uword_to_pointer (p[0], vnet_feature_arc_registration_t *);
      arc_index = areg->feature_arc_index;

      next = creg->next;
      creg->next_in_arc = fm->next_constraint_by_arc[arc_index];
      fm->next_constraint_by_arc[arc_index] = creg;

      /* next */
      creg = next;
    }


  areg = fm->next_arc;
  while (areg)
    {
      clib_error_t *error;
      vnet_feature_config_main_t *cm;
      vnet_config_main_t *vcm;
      char **features_in_order, *last_feature;

      arc_index = areg->feature_arc_index;
      cm = &fm->feature_config_mains[arc_index];
      vcm = &cm->config_main;
      if ((error = vnet_feature_arc_init
	   (vm, vcm, areg->start_nodes, areg->n_start_nodes,
	    areg->last_in_arc,
	    fm->next_feature_by_arc[arc_index],
	    fm->next_constraint_by_arc[arc_index],
	    &fm->feature_nodes[arc_index])))
	{
	  clib_error_report (error);
	  os_exit (1);
	}

      features_in_order = fm->feature_nodes[arc_index];

      /* If specified, verify that the last node in the arc is actually last */
      if (areg->last_in_arc && vec_len (features_in_order) > 0)
	{
	  last_feature = features_in_order[vec_len (features_in_order) - 1];
	  if (strncmp (areg->last_in_arc, last_feature,
		       strlen (areg->last_in_arc)))
	    clib_warning
	      ("WARNING: %s arc: last node is %s, but expected %s!",
	       areg->arc_name, last_feature, areg->last_in_arc);
	}

      fm->next_feature_by_name[arc_index] =
	hash_create_string (0, sizeof (uword));
      freg = fm->next_feature_by_arc[arc_index];

      while (freg)
	{
	  hash_set_mem (fm->next_feature_by_name[arc_index],
			freg->node_name, pointer_to_uword (freg));
	  freg = freg->next_in_arc;
	}

      /* next */
      areg = areg->next;
      arc_index++;
    }

  return 0;
}

VLIB_INIT_FUNCTION (vnet_feature_init);

u8
vnet_get_feature_arc_index (const char *s)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_arc_registration_t *reg;
  uword *p;

  p = hash_get_mem (fm->arc_index_by_name, s);
  if (p == 0)
    return ~0;

  reg = uword_to_pointer (p[0], vnet_feature_arc_registration_t *);
  return reg->feature_arc_index;
}

vnet_feature_registration_t *
vnet_get_feature_reg (const char *arc_name, const char *node_name)
{
  u8 arc_index;

  arc_index = vnet_get_feature_arc_index (arc_name);
  if (arc_index == (u8) ~ 0)
    return 0;

  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_registration_t *reg;
  uword *p;

  p = hash_get_mem (fm->next_feature_by_name[arc_index], node_name);
  if (p == 0)
    return 0;

  reg = uword_to_pointer (p[0], vnet_feature_registration_t *);
  return reg;
}

u32
vnet_get_feature_index (u8 arc, const char *s)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_registration_t *reg;
  uword *p;

  if (s == 0)
    return ~0;

  p = hash_get_mem (fm->next_feature_by_name[arc], s);
  if (p == 0)
    return ~0;

  reg = uword_to_pointer (p[0], vnet_feature_registration_t *);
  return reg->feature_index;
}

int
vnet_feature_enable_disable_with_index (u8 arc_index, u32 feature_index,
					u32 sw_if_index, int enable_disable,
					void *feature_config,
					u32 n_feature_config_bytes)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  i16 feature_count;
  u32 ci;

  if (arc_index == (u8) ~ 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (feature_index == ~0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  cm = &fm->feature_config_mains[arc_index];
  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  vec_validate (fm->feature_count_by_sw_if_index[arc_index], sw_if_index);
  feature_count = fm->feature_count_by_sw_if_index[arc_index][sw_if_index];

  if (!enable_disable && feature_count < 1)
    return 0;

  ci = (enable_disable
	? vnet_config_add_feature
	: vnet_config_del_feature)
    (vlib_get_main (), &cm->config_main, ci, feature_index, feature_config,
     n_feature_config_bytes);
  if (ci == ~0)
    {
      return 0;
    }
  cm->config_index_by_sw_if_index[sw_if_index] = ci;

  /* update feature count */
  enable_disable = (enable_disable > 0);
  feature_count += enable_disable ? 1 : -1;
  ASSERT (feature_count >= 0);

  fm->sw_if_index_has_features[arc_index] =
    clib_bitmap_set (fm->sw_if_index_has_features[arc_index], sw_if_index,
		     (feature_count > 0));
  fm->feature_count_by_sw_if_index[arc_index][sw_if_index] = feature_count;

  vnet_feature_reg_invoke (sw_if_index, arc_index, (feature_count > 0));

  return 0;
}

int
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config, u32 n_feature_config_bytes)
{
  u32 feature_index;
  u8 arc_index;

  log_info ("vfed: start for arc_name %s", arc_name);

  arc_index = vnet_get_feature_arc_index (arc_name);

  log_info ("vfed: arc_index %u", arc_index);

  if (arc_index == (u8) ~ 0)
    return VNET_API_ERROR_INVALID_VALUE;

  feature_index = vnet_get_feature_index (arc_index, node_name);

  log_info ("vfed: feature_index %u", feature_index);

  return vnet_feature_enable_disable_with_index (arc_index, feature_index,
						 sw_if_index, enable_disable,
						 feature_config,
						 n_feature_config_bytes);
}

int
vnet_feature_is_enabled (const char *arc_name, const char *feature_node_name,
			 u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  vnet_config_main_t *ccm;
  vnet_config_t *current_config;
  vnet_config_feature_t *f;
  u32 feature_index;
  u32 ci;
  u8 arc_index;
  u32 *p;

  arc_index = vnet_get_feature_arc_index (arc_name);

  /* No such arc? */
  if (arc_index == (u8) ~ 0)
    return VNET_API_ERROR_INVALID_VALUE;

  feature_index = vnet_get_feature_index (arc_index, feature_node_name);

  /* No such feature? */
  if (feature_index == (u32) ~ 0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  cm = &fm->feature_config_mains[arc_index];

  if (sw_if_index < vec_len (cm->config_index_by_sw_if_index))
    ci = vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
  else
    /* sw_if_index out of range, certainly not enabled */
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* No features were ever configured? */
  if (ci == ~0)
    return 0;

  ccm = &cm->config_main;

  p = heap_elt_at_index (ccm->config_string_heap, ci);

  current_config = pool_elt_at_index (ccm->config_pool, p[-1]);

  /* Find feature with the required index */
  vec_foreach (f, current_config->features)
  {
    if (f->feature_index == feature_index)
      /* Feature was enabled */
      return 1;
  }
  /* feature wasn't enabled */
  return 0;
}

u32
vnet_feature_get_end_node (u8 arc_index, u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u32 ci;

  if (arc_index == (u8) ~0)
    return VNET_API_ERROR_INVALID_VALUE;

  cm = &fm->feature_config_mains[arc_index];
  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  return (vnet_config_get_end_node (vlib_get_main (), &cm->config_main, ci));
}

u32
vnet_feature_reset_end_node (u8 arc_index, u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u32 ci;

  cm = &fm->feature_config_mains[arc_index];
  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  ci = vnet_config_reset_end_node (vlib_get_main (), &cm->config_main, ci);

  if (ci != ~0)
    cm->config_index_by_sw_if_index[sw_if_index] = ci;

  i16 feature_count;

  if (NULL == fm->feature_count_by_sw_if_index ||
      vec_len (fm->feature_count_by_sw_if_index) <= arc_index ||
      vec_len (fm->feature_count_by_sw_if_index[arc_index]) <= sw_if_index)
    feature_count = 0;
  else
    feature_count = fm->feature_count_by_sw_if_index[arc_index][sw_if_index];

  vnet_feature_reg_invoke (sw_if_index, arc_index, (feature_count > 0));

  return ci;
}

u32
vnet_feature_modify_end_node (u8 arc_index,
			      u32 sw_if_index, u32 end_node_index)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u32 ci;

  if (arc_index == (u8) ~ 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (end_node_index == ~0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  cm = &fm->feature_config_mains[arc_index];
  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  ci = vnet_config_modify_end_node (vlib_get_main (), &cm->config_main,
				    ci, end_node_index);

  if (ci != ~0)
    cm->config_index_by_sw_if_index[sw_if_index] = ci;

  i16 feature_count;

  if (NULL == fm->feature_count_by_sw_if_index ||
      vec_len (fm->feature_count_by_sw_if_index) <= arc_index ||
      vec_len (fm->feature_count_by_sw_if_index[arc_index]) <= sw_if_index)
    feature_count = 0;
  else
    feature_count = fm->feature_count_by_sw_if_index[arc_index][sw_if_index];

  vnet_feature_reg_invoke (sw_if_index, arc_index, (feature_count > 0));

  return ci;
}

static int
feature_cmp (void *a1, void *a2)
{
  vnet_feature_registration_t *reg1 = a1;
  vnet_feature_registration_t *reg2 = a2;

  return (int) reg1->feature_index - reg2->feature_index;
}

/** Display the set of available driver features.
    Useful for verifying that expected features are present
*/

static clib_error_t *
show_features_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_arc_registration_t *areg;
  vnet_feature_registration_t *freg;
  vnet_feature_registration_t *feature_regs = 0;
  int verbose = 0;

  if (unformat (input, "verbose"))
    verbose = 1;

  vlib_cli_output (vm, "Available feature paths");

  areg = fm->next_arc;
  while (areg)
    {
      if (verbose)
	vlib_cli_output (vm, "[%2d] %s:", areg->feature_arc_index,
			 areg->arc_name);
      else
	vlib_cli_output (vm, "%s:", areg->arc_name);

      freg = fm->next_feature_by_arc[areg->feature_arc_index];
      while (freg)
	{
	  vec_add1 (feature_regs, freg[0]);
	  freg = freg->next_in_arc;
	}

      vec_sort_with_function (feature_regs, feature_cmp);

      vec_foreach (freg, feature_regs)
      {
	if (verbose)
	  vlib_cli_output (vm, "  [%2d]: %s\n", freg->feature_index,
			   freg->node_name);
	else
	  vlib_cli_output (vm, "  %s\n", freg->node_name);
      }
      vec_reset_length (feature_regs);
      /* next */
      areg = areg->next;
    }
  vec_free (feature_regs);

  return 0;
}

/*?
 * Display the set of available driver features
 *
 * @cliexpar
 * Example:
 * @cliexcmd{show features [verbose]}
 * @cliexend
 * @endparblock
?*/
VLIB_CLI_COMMAND (show_features_command, static) = {
  .path = "show features",
  .short_help = "show features [verbose]",
  .function = show_features_command_fn,
};

/** Display the set of driver features configured on a specific interface
  * Called by "show interface" handler
 */

void
vnet_interface_features_show (vlib_main_t * vm, u32 sw_if_index, int verbose)
{
  vnet_feature_main_t *fm = &feature_main;
  u32 node_index, current_config_index;
  u16 feature_arc;
  vnet_feature_config_main_t *cm = fm->feature_config_mains;
  vnet_feature_arc_registration_t *areg;
  vnet_config_main_t *vcm;
  vnet_config_t *cfg;
  u32 cfg_index;
  vnet_config_feature_t *feat;
  vlib_node_t *n;
  int i;

  vlib_cli_output (vm, "Feature paths configured on %U...",
		   format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);

  areg = fm->next_arc;
  while (areg)
    {
      feature_arc = areg->feature_arc_index;
      vcm = &(cm[feature_arc].config_main);

      vlib_cli_output (vm, "\n%s:", areg->arc_name);
      areg = areg->next;

      if (!vnet_have_features (feature_arc, sw_if_index))
	{
	  vlib_cli_output (vm, "  none configured");
	  continue;
	}

      current_config_index =
	vec_elt (cm[feature_arc].config_index_by_sw_if_index, sw_if_index);
      cfg_index =
	vec_elt (vcm->config_pool_index_by_user_index, current_config_index);
      cfg = pool_elt_at_index (vcm->config_pool, cfg_index);

      for (i = 0; i < vec_len (cfg->features); i++)
	{
	  feat = cfg->features + i;
	  node_index = feat->node_index;
	  n = vlib_get_node (vm, node_index);
	  if (verbose)
	    vlib_cli_output (vm, "  [%2d] %v", feat->feature_index, n->name);
	  else
	    vlib_cli_output (vm, "  %v", n->name);
	}
      if (verbose)
	{
	  n =
	    vlib_get_node (vm,
			   vcm->end_node_indices_by_user_index
			   [current_config_index]);
	  vlib_cli_output (vm, "  [end] %v", n->name);
	}
    }
}

static clib_error_t *
set_interface_features_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  u8 *arc_name = 0;
  u8 *feature_name = 0;
  u32 sw_if_index = ~0;
  u8 enable = 1;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U %s arc %s", unformat_vnet_sw_interface, vnm,
	   &sw_if_index, &feature_name, &arc_name))
	;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (!feature_name || !arc_name)
    {
      error = clib_error_return (0, "Both feature name and arc required...");
      goto done;
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Interface not specified...");
      goto done;
    }

  vec_add1 (arc_name, 0);
  vec_add1 (feature_name, 0);

  u8 arc_index;

  arc_index = vnet_get_feature_arc_index ((const char *) arc_name);

  if (arc_index == (u8) ~ 0)
    {
      error =
	clib_error_return (0, "Unknown arc name (%s)... ",
			   (const char *) arc_name);
      goto done;
    }

  vnet_feature_registration_t *reg;
  reg =
    vnet_get_feature_reg ((const char *) arc_name,
			  (const char *) feature_name);
  if (reg == 0)
    {
      error =
	clib_error_return (0,
			   "Feature (%s) not registered to arc (%s)... See 'show features verbose' for valid feature/arc combinations. ",
			   feature_name, arc_name);
      goto done;
    }
  if (reg->enable_disable_cb)
    error = reg->enable_disable_cb (sw_if_index, enable);
  if (!error)
    vnet_feature_enable_disable ((const char *) arc_name,
				 (const char *) feature_name, sw_if_index,
				 enable, 0, 0);

done:
  vec_free (feature_name);
  vec_free (arc_name);
  unformat_free (line_input);
  return error;
}

/*?
 * Set feature for given interface
 *
 * @cliexpar
 * Example:
 * @cliexcmd{set interface feature GigabitEthernet2/0/0 ip4_flow_classify arc ip4_unicast}
 * @cliexend
 * @endparblock
?*/
VLIB_CLI_COMMAND (set_interface_feature_command, static) = {
  .path = "set interface feature",
  .short_help = "set interface feature <intfc> <feature_name> arc <arc_name> "
      "[disable]",
  .function = set_interface_features_command_fn,
};

static clib_error_t *
vnet_feature_add_del_sw_interface (vnet_main_t * vnm, u32 sw_if_index,
				   u32 is_add)
{
  vnet_feature_main_t *fm = &feature_main;
  const vnet_feature_arc_registration_t *far;

  if (is_add)
    return 0;

  /*
   * remove all enabled features from an interface on deletion
   */
  for (far = fm->next_arc; far != 0; far = far->next)
    {
      const u8 arc_index = far->feature_arc_index;
      vnet_feature_config_main_t *cm =
	vec_elt_at_index (fm->feature_config_mains, arc_index);
      const u32 ci =
	vec_len (cm->config_index_by_sw_if_index) <=
	sw_if_index ? ~0 : vec_elt (cm->config_index_by_sw_if_index,
				    sw_if_index);

      if (~0 == ci)
	continue;

      fm->sw_if_index_has_features[arc_index] =
	clib_bitmap_set (fm->sw_if_index_has_features[arc_index], sw_if_index,
			 0);

      vnet_feature_reg_invoke (sw_if_index, arc_index, 0);

      if (vec_len (fm->feature_count_by_sw_if_index[arc_index]) > sw_if_index)
	vec_elt (fm->feature_count_by_sw_if_index[arc_index], sw_if_index) =
	  0;

      vec_elt (cm->config_index_by_sw_if_index, sw_if_index) = ~0;
      vnet_config_del (&cm->config_main, ci);
    }

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION_PRIO (vnet_feature_add_del_sw_interface,
					 VNET_ITF_FUNC_PRIORITY_HIGH);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
