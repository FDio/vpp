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

#include <plugins/abf/abf_policy.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

/**
 * FIB node type the attachment is registered
 */
fib_node_type_t abf_policy_fib_node_type;

/**
 * Pool of ABF objects
 */
static abf_policy_t *abf_policy_pool;

/**
 * DB of ABF policy objects
 *  - policy ID to index conversion.
 */
static uword *abf_policy_db;


abf_policy_t *
abf_policy_get (u32 index)
{
  return (pool_elt_at_index (abf_policy_pool, index));
}

static u32
abf_policy_get_index (const abf_policy_t * abf)
{
  return (abf - abf_policy_pool);
}

static abf_policy_t *
abf_policy_find_i (u32 policy_id)
{
  u32 api;

  api = abf_policy_find (policy_id);

  if (INDEX_INVALID != api)
    return (abf_policy_get (api));

  return (NULL);
}

u32
abf_policy_find (u32 policy_id)
{
  uword *p;

  p = hash_get (abf_policy_db, policy_id);

  if (NULL != p)
    return (p[0]);

  return (INDEX_INVALID);
}


int
abf_policy_update (u32 policy_id,
		   u32 acl_index, const fib_route_path_t * rpaths)
{
  abf_policy_t *ap;
  u32 api;

  api = abf_policy_find (policy_id);

  if (INDEX_INVALID == api)
    {
      /*
       * create a new policy
       */
      pool_get (abf_policy_pool, ap);

      api = ap - abf_policy_pool;
      fib_node_init (&ap->ap_node, abf_policy_fib_node_type);
      ap->ap_acl = acl_index;
      ap->ap_id = policy_id;
      ap->ap_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					 FIB_PATH_LIST_FLAG_NO_URPF), rpaths);

      /*
       * become a child of the path list so we get poked when
       * the forwarding changes.
       */
      ap->ap_sibling = fib_path_list_child_add (ap->ap_pl,
						abf_policy_fib_node_type,
						api);

      /*
       * add this new policy to the DB
       */
      hash_set (abf_policy_db, policy_id, api);

      /*
       * take a lock on behalf of the CLI/API creation
       */
      fib_node_lock (&ap->ap_node);
    }
  else
    {
      /*
       * update an existing policy.
       * - add the path to the path-list and swap our ancestry
       * - backwalk to poke all attachments to update
       */
      fib_node_index_t old_pl;

      ap = abf_policy_get (api);
      old_pl = ap->ap_pl;
      if (ap->ap_acl != acl_index)
	{
	  /* Should change this error code to something more descriptive */
	  return (VNET_API_ERROR_INVALID_VALUE);
	}

      if (FIB_NODE_INDEX_INVALID != old_pl)
	{
	  ap->ap_pl = fib_path_list_copy_and_path_add (old_pl,
						       (FIB_PATH_LIST_FLAG_SHARED
							|
							FIB_PATH_LIST_FLAG_NO_URPF),
						       rpaths);
	  fib_path_list_child_remove (old_pl, ap->ap_sibling);
	}
      else
	{
	  ap->ap_pl = fib_path_list_create ((FIB_PATH_LIST_FLAG_SHARED |
					     FIB_PATH_LIST_FLAG_NO_URPF),
					    rpaths);
	}

      ap->ap_sibling = fib_path_list_child_add (ap->ap_pl,
						abf_policy_fib_node_type,
						api);

      fib_node_back_walk_ctx_t ctx = {
	.fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
      };

      fib_walk_sync (abf_policy_fib_node_type, api, &ctx);
    }
  return (0);
}

static void
abf_policy_destroy (abf_policy_t * ap)
{
  /*
   * this ABF should not be a sibling on the path list, since
   * that was removed when the API config went
   */
  ASSERT (ap->ap_sibling == ~0);
  ASSERT (ap->ap_pl == FIB_NODE_INDEX_INVALID);

  hash_unset (abf_policy_db, ap->ap_id);
  pool_put (abf_policy_pool, ap);
}

int
abf_policy_delete (u32 policy_id, const fib_route_path_t * rpaths)
{
  abf_policy_t *ap;
  u32 api;

  api = abf_policy_find (policy_id);

  if (INDEX_INVALID == api)
    {
      /*
       * no such policy
       */
      return (VNET_API_ERROR_INVALID_VALUE);
    }
  else
    {
      /*
       * update an existing policy.
       * - add the path to the path-list and swap our ancestry
       * - backwalk to poke all attachments to update
       */
      fib_node_index_t old_pl;

      ap = abf_policy_get (api);
      old_pl = ap->ap_pl;

      fib_path_list_lock (old_pl);
      ap->ap_pl =
	fib_path_list_copy_and_path_remove (ap->ap_pl,
					    (FIB_PATH_LIST_FLAG_SHARED |
					     FIB_PATH_LIST_FLAG_NO_URPF),
					    rpaths);

      fib_path_list_child_remove (old_pl, ap->ap_sibling);
      ap->ap_sibling = ~0;

      if (FIB_NODE_INDEX_INVALID == ap->ap_pl)
	{
	  /*
	   * no more paths on this policy. It's toast
	   * remove the CLI/API's lock
	   */
	  fib_node_unlock (&ap->ap_node);
	}
      else
	{
	  ap->ap_sibling = fib_path_list_child_add (ap->ap_pl,
						    abf_policy_fib_node_type,
						    api);

	  fib_node_back_walk_ctx_t ctx = {
	    .fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
	  };

	  fib_walk_sync (abf_policy_fib_node_type, api, &ctx);
	}
      fib_path_list_unlock (old_pl);
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
  int rv = 0;

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

      rv = abf_policy_update (policy_id, acl_index, rpaths);
      /* Should change this error code to something more descriptive */
      if (rv == VNET_API_ERROR_INVALID_VALUE)
	{
	  vlib_cli_output (vm,
			   "ACL index must match existing ACL index in policy");
	  return 0;
	}
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
format_abf (u8 * s, va_list * args)
{
  abf_policy_t *ap = va_arg (*args, abf_policy_t *);

  s = format (s, "abf:[%d]: policy:%d acl:%d",
	      ap - abf_policy_pool, ap->ap_id, ap->ap_acl);
  s = format (s, "\n ");
  if (FIB_NODE_INDEX_INVALID == ap->ap_pl)
    {
      s = format (s, "no forwarding");
    }
  else
    {
      s = fib_path_list_format (ap->ap_pl, s);
    }

  return (s);
}

void
abf_policy_walk (abf_policy_walk_cb_t cb, void *ctx)
{
  u32 api;

  /* *INDENT-OFF* */
  pool_foreach_index(api, abf_policy_pool,
  ({
    if (!cb(api, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
abf_show_policy_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id;
  abf_policy_t *ap;

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
      pool_foreach(ap, abf_policy_pool,
      ({
        vlib_cli_output(vm, "%U", format_abf, ap);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      ap = abf_policy_find_i (policy_id);

      if (NULL != ap)
	vlib_cli_output (vm, "%U", format_abf, ap);
      else
	vlib_cli_output (vm, "Invalid policy ID:%d", policy_id);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_policy_show_policy_cmd_node, static) = {
  .path = "show abf policy",
  .function = abf_show_policy_cmd,
  .short_help = "show abf policy <value>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static fib_node_t *
abf_policy_get_node (fib_node_index_t index)
{
  abf_policy_t *ap = abf_policy_get (index);
  return (&(ap->ap_node));
}

static abf_policy_t *
abf_policy_get_from_node (fib_node_t * node)
{
  return ((abf_policy_t *) (((char *) node) -
			    STRUCT_OFFSET_OF (abf_policy_t, ap_node)));
}

static void
abf_policy_last_lock_gone (fib_node_t * node)
{
  abf_policy_destroy (abf_policy_get_from_node (node));
}

/*
 * A back walk has reached this ABF policy
 */
static fib_node_back_walk_rc_t
abf_policy_back_walk_notify (fib_node_t * node,
			     fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-stack the fmask on the n-eos of the via
   */
  abf_policy_t *abf = abf_policy_get_from_node (node);

  /*
   * propagate further up the graph.
   * we can do this synchronously since the fan out is small.
   */
  fib_walk_sync (abf_policy_fib_node_type, abf_policy_get_index (abf), ctx);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t abf_policy_vft = {
  .fnv_get = abf_policy_get_node,
  .fnv_last_lock = abf_policy_last_lock_gone,
  .fnv_back_walk = abf_policy_back_walk_notify,
};

static clib_error_t *
abf_policy_init (vlib_main_t * vm)
{
  abf_policy_fib_node_type = fib_node_register_new_type (&abf_policy_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (abf_policy_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
