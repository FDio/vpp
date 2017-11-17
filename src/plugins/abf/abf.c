/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <plugins/abf/abf.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

/**
 * FIB node type the attachment is registered
 */
fib_node_type_t abf_fib_node_type;

/**
 * Pool of ABF objects
 */
static abf_t *abf_pool;

/**
 * DB of ABF policy objects
 *  - policy ID to index conversion.
 */
static uword *abf_db;


abf_t *
abf_get (u32 index)
{
  return (pool_elt_at_index (abf_pool, index));
}

static u32
abf_get_index (const abf_t * abf)
{
  return (abf - abf_pool);
}

static abf_t *
abf_find_i (u32 policy_id)
{
  u32 abfi;

  abfi = abf_find (policy_id);

  if (INDEX_INVALID != abfi)
    return (abf_get (abfi));

  return (NULL);
}

u32
abf_find (u32 policy_id)
{
  uword *p;

  p = hash_get (abf_db, policy_id);

  if (NULL != p)
    return (p[0]);

  return (INDEX_INVALID);
}


void
abf_policy_update (u32 policy_id,
		   u32 acl_index, const fib_route_path_t * rpaths)
{
  abf_t *abf;
  u32 abfi;

  abfi = abf_find (policy_id);

  if (INDEX_INVALID == abfi)
    {
      /*
       * create a new policy
       */
      pool_get (abf_pool, abf);

      abfi = abf - abf_pool;
      fib_node_init (&abf->abf_node, abf_fib_node_type);
      abf->abf_acl = acl_index;
      abf->abf_id = policy_id;
      abf->abf_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					   FIB_PATH_LIST_FLAG_NO_URPF),
					  rpaths);

      /*
       * become a child of the path list so we get poked when
       * the forwarding changes.
       */
      abf->abf_sibling = fib_path_list_child_add (abf->abf_pl,
						  abf_fib_node_type, abfi);

      /*
       * add this new policy to the DB
       */
      hash_set (abf_db, policy_id, abfi);

      /*
       * take a lock on behalf of the CLI/API creation
       */
      fib_node_lock (&abf->abf_node);
    }
  else
    {
      /*
       * update an existing policy.
       * - add the path to the path-list and swap our ancestory
       * - backwalk to poke all attachments to update
       */
      fib_node_index_t old_pl;

      abf = abf_get (abfi);
      old_pl = abf->abf_pl;

      if (FIB_NODE_INDEX_INVALID != old_pl)
	{
	  abf->abf_pl = fib_path_list_copy_and_path_add (old_pl,
							 (FIB_PATH_LIST_FLAG_SHARED
							  |
							  FIB_PATH_LIST_FLAG_NO_URPF),
							 rpaths);
	  fib_path_list_child_remove (old_pl, abf->abf_sibling);
	}
      else
	{
	  abf->abf_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					       FIB_PATH_LIST_FLAG_NO_URPF),
					      rpaths);
	}

      abf->abf_sibling = fib_path_list_child_add (abf->abf_pl,
						  abf_fib_node_type, abfi);

      fib_node_back_walk_ctx_t ctx = {
	.fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
      };

      fib_walk_sync (abf_fib_node_type, abfi, &ctx);
    }
}

static void
abf_destroy (abf_t * abf)
{
  /*
   * this ABF should not be a sibling on the path list, since
   * that was removed when the API config went
   */
  ASSERT (abf->abf_sibling == ~0);
  ASSERT (abf->abf_pl == FIB_NODE_INDEX_INVALID);

  pool_put (abf_pool, abf);
}

int
abf_policy_delete (u32 policy_id, const fib_route_path_t * rpaths)
{
  abf_t *abf;
  u32 abfi;

  abfi = abf_find (policy_id);

  if (INDEX_INVALID == abfi)
    {
      /*
       * no such policy
       */
      return (-1);
    }
  else
    {
      /*
       * update an existing policy.
       * - add the path to the path-list and swap our ancestory
       * - backwalk to poke all attachments to update
       */
      fib_node_index_t old_pl;

      abf = abf_get (abfi);
      old_pl = abf->abf_pl;

      abf->abf_pl =
	fib_path_list_copy_and_path_remove (abf->abf_pl,
					    (FIB_PATH_LIST_FLAG_SHARED |
					     FIB_PATH_LIST_FLAG_NO_URPF),
					    rpaths);

      fib_path_list_child_remove (old_pl, abf->abf_sibling);
      abf->abf_sibling = ~0;

      if (FIB_NODE_INDEX_INVALID == abf->abf_pl)
	{
	  /*
	   * no more paths on this policy. It's toast
	   * remove the CLI/API's lock
	   */
	  fib_node_unlock (&abf->abf_node);
	}
      else
	{
	  abf->abf_sibling = fib_path_list_child_add (abf->abf_pl,
						      abf_fib_node_type,
						      abfi);

	  fib_node_back_walk_ctx_t ctx = {
	    .fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
	  };

	  fib_walk_sync (abf_fib_node_type, abfi, &ctx);
	}
    }

  return (0);
}

static clib_error_t *
abf_policy_cmd (vlib_main_t * vm,
		unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 acl_index, policy_id;
  fib_route_path_t *rpaths = NULL, rpath;
  u32 is_del;

  is_del = 0;
  acl_index = INDEX_INVALID;
  policy_id = INDEX_INVALID;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "acl %d", &acl_index))
	;
      else if (unformat (line_input, "id %d", &policy_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath))
	vec_add1 (rpaths, rpath);
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  if (INDEX_INVALID == policy_id)
    {
      vlib_cli_output (vm, "Specify a Policy ID");
      return 0;
    }

  if (!is_del)
    {
      if (INDEX_INVALID == acl_index)
	{
	  vlib_cli_output (vm, "ACL index must be set");
	  return 0;
	}

      abf_policy_update (policy_id, acl_index, rpaths);
    }
  else
    {
      abf_policy_delete (policy_id, rpaths);
    }

  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Create an ABF policy.
 */
VLIB_CLI_COMMAND (abf_policy_cmd_node, static) = {
  .path = "abf policy",
  .function = abf_policy_cmd,
  .short_help = "abf policy [add|del] id <index> acl <index> via ...",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static u8 *
format_abf (u8 * s, va_list * ap)
{
  abf_t *abf = va_arg (*ap, abf_t *);

  s = format (s, "abf:[%d]: policy:%d acl:%d",
	      abf - abf_pool, abf->abf_id, abf->abf_acl);
  s = format (s, "\n ");
  if (FIB_NODE_INDEX_INVALID == abf->abf_pl)
    {
      s = format (s, "no forwarding");
    }
  else
    {
      s = fib_path_list_format (abf->abf_pl, s);
    }

  return (s);
}

static clib_error_t *
abf_show_policy_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id;
  abf_t *abf;

  policy_id = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &policy_id))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == policy_id)
    {
      /* *INDENT-OFF* */
      pool_foreach(abf, abf_pool,
      ({
        vlib_cli_output(vm, "%U", format_abf, abf);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      abf = abf_find_i (policy_id);

      if (NULL != abf)
	vlib_cli_output (vm, "%U", format_abf, abf);
      else
	vlib_cli_output (vm, "Invalid policy ID:%d", policy_id);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_show_policy_cmd_node, static) = {
  .path = "show abf policy",
  .function = abf_show_policy_cmd,
  .short_help = "show abf policy <value>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static fib_node_t *
abf_get_node (fib_node_index_t index)
{
  abf_t *abf = abf_get (index);
  return (&(abf->abf_node));
}

static abf_t *
abf_get_from_node (fib_node_t * node)
{
  return ((abf_t *) (((char *) node) - STRUCT_OFFSET_OF (abf_t, abf_node)));
}

static void
abf_last_lock_gone (fib_node_t * node)
{
  abf_destroy (abf_get_from_node (node));
}

/*
 * A back walk has reached this ABF policy
 */
static fib_node_back_walk_rc_t
abf_back_walk_notify (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-stack the fmask on the n-eos of the via
   */
  abf_t *abf = abf_get_from_node (node);

  /*
   * propagate further up the graph.
   * we can do this synchronously since the fan out is small.
   */
  fib_walk_sync (abf_fib_node_type, abf_get_index (abf), ctx);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t abf_vft = {
  .fnv_get = abf_get_node,
  .fnv_last_lock = abf_last_lock_gone,
  .fnv_back_walk = abf_back_walk_notify,
};

static clib_error_t *
abf_init (vlib_main_t * vm)
{
  abf_fib_node_type = fib_node_register_new_type (&abf_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (abf_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "ACL based Forwarding",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
