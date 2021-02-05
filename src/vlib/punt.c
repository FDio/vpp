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

#include <vlib/punt.h>

/**
 * The last allocated punt reason
 * Value 0 is reserved for invalid index.
 */
static vlib_punt_reason_t punt_reason_last = 1;

/**
 * Counters per punt-reason
 */
vlib_combined_counter_main_t punt_counters = {
  .name = "punt",
  .stat_segment_name = "/net/punt",
};

/**
 * A punt reason
 */
typedef struct punt_reason_data_t_
{
  /**
   * The reason name
   */
  u8 *pd_name;

  /**
   * The allocated reason value
   */
  vlib_punt_reason_t pd_reason;

  /**
   * Clients/owners that have registered this reason
   */
  u32 *pd_owners;

  /**
   * clients interested/listening to this reason
   */
  u32 pd_users;

  /**
   * function to invoke if a client becomes interested in the code.
   */
  punt_interested_listener_t pd_fn;

  /**
   * Data to pass to the callback
   */
  void *pd_data;

  /**
   * Flags associated to the reason
   */
  u32 flags;

  /**
   * Formatting function for flags;
   */
  format_function_t *flags_format;
} punt_reason_data_t;

/**
 * data for each punt reason
 */
static punt_reason_data_t *punt_reason_data;

typedef enum punt_format_flags_t_
{
  PUNT_FORMAT_FLAG_NONE = 0,
  PUNT_FORMAT_FLAG_DETAIL = (1 << 0),
} punt_format_flags_t;

/**
 * A registration, by a client, to direct punted traffic to a given node
 */
typedef struct punt_reg_t_
{
  /**
   * Reason the packets were punted
   */
  vlib_punt_reason_t pr_reason;

  /**
   * number of clients that have made this registration
   */
  u16 pr_locks;

  /**
   * The edge from the punt dispatch node to the requested node
   */
  u16 pr_edge;

  /**
   * node-index to send punted packets to
   */
  u32 pr_node_index;
} punt_reg_t;

/**
 * Pool of registrations
 */
static punt_reg_t *punt_reg_pool;

/**
 * A DB of all the register nodes against punt reason and node index
 */
static uword *punt_reg_db;

/**
 * A DB used in the DP per-reason to dispatch packets to the requested nodes.
 * this is a vector of edges per-reason
 */
u16 **punt_dp_db;

/**
 * A client using the punt serivce and its registrations
 */
typedef struct punt_client_t_
{
  /**
   * The name of the client
   */
  u8 *pc_name;

  /**
   * The registrations is has made
   */
  u32 *pc_regs;
} punt_client_t;

/**
 * Pool of clients
 */
static punt_client_t *punt_client_pool;

/**
 * DB of clients key'd by their name
 */
static uword *punt_client_db;

u8 *
format_vlib_punt_reason (u8 * s, va_list * args)
{
  vlib_punt_reason_t pr = va_arg (*args, int);
  format_function_t *flags_format = punt_reason_data[pr].flags_format;
  u32 flags = punt_reason_data[pr].flags;
  if (flags_format)
    return (format (s, "[%d] %v flags: %U", pr, punt_reason_data[pr].pd_name,
		    flags_format, flags));
  else
    return (format (s, "[%d] %v", pr, punt_reason_data[pr].pd_name));
}

vlib_punt_hdl_t
vlib_punt_client_register (const char *who)
{
  u8 *pc_name;
  uword *p;
  u32 pci;

  pc_name = format (NULL, "%s", who);
  p = hash_get_mem (punt_client_db, pc_name);

  if (NULL == p)
    {
      punt_client_t *pc;

      pool_get (punt_client_pool, pc);
      pci = pc - punt_client_pool;

      pc->pc_name = pc_name;

      hash_set_mem (punt_client_db, pc->pc_name, pci);
    }
  else
    {
      pci = p[0];
      vec_free (pc_name);
    }

  return (pci);
}

static int
punt_validate_client (vlib_punt_hdl_t client)
{
  return (!pool_is_free_index (punt_client_pool, client));
}

static u64
punt_reg_mk_key (vlib_punt_reason_t reason, u32 node_index)
{
  return (((u64) node_index) << 32 | reason);
}

static u32
punt_reg_find (vlib_punt_reason_t reason, u32 node_index)
{
  uword *p;

  p = hash_get (punt_reg_db, punt_reg_mk_key (reason, node_index));

  if (p)
    return p[0];

  return ~0;
}

static void
punt_reg_add (const punt_reg_t * pr)
{
  hash_set (punt_reg_db, punt_reg_mk_key (pr->pr_reason,
					  pr->pr_node_index),
	    pr - punt_reg_pool);
}

static void
punt_reg_remove (const punt_reg_t * pr)
{
  hash_unset (punt_reg_db, punt_reg_mk_key (pr->pr_reason,
					    pr->pr_node_index));
}

/**
 * reconstruct the DP per-reason DB
 */
static void
punt_reg_mk_dp (vlib_punt_reason_t reason)
{
  u32 pri, *prip, *pris;
  const punt_reg_t *pr;
  u16 *edges, *old;
  u64 key;

  pris = NULL;
  edges = NULL;
  vec_validate (punt_dp_db, reason);

  old = punt_dp_db[reason];

  /* *INDENT-OFF* */
  hash_foreach (key, pri, punt_reg_db,
    ({
      vec_add1(pris, pri);
    }));
  /* *INDENT-ON* */

  /*
   * A check for an empty vector is done in the DP, so the a zero
   * length vector here is ok
   */
  vec_foreach (prip, pris)
  {
    pr = pool_elt_at_index (punt_reg_pool, *prip);

    if (pr->pr_reason == reason)
      vec_add1 (edges, pr->pr_edge);
  }

  /* atomic update of the DP */
  punt_dp_db[reason] = edges;

  vec_free (old);
}

int
vlib_punt_register (vlib_punt_hdl_t client,
		    vlib_punt_reason_t reason, const char *node_name)
{
  vlib_node_t *punt_to, *punt_from;
  punt_client_t *pc;
  vlib_main_t *vm;
  punt_reg_t *pr;
  u32 pri;

  if (reason >= punt_reason_last)
    return -1;
  if (!punt_validate_client (client))
    return -2;

  vm = vlib_get_main ();
  pc = pool_elt_at_index (punt_client_pool, client);
  punt_to = vlib_get_node_by_name (vm, (u8 *) node_name);
  punt_from = vlib_get_node_by_name (vm, (u8 *) "punt-dispatch");

  /*
   * find a global matching registration
   */
  pri = punt_reg_find (reason, punt_to->index);

  if (~0 != pri)
    {
      u32 pos;

      pos = vec_search (pc->pc_regs, pri);

      if (~0 != pos)
	{
	  /* duplicate registration for this client */
	  return -1;
	}

      pr = pool_elt_at_index (punt_reg_pool, pri);
    }
  else
    {
      pool_get (punt_reg_pool, pr);

      pr->pr_reason = reason;
      pr->pr_node_index = punt_to->index;
      pr->pr_edge = vlib_node_add_next (vm,
					punt_from->index, pr->pr_node_index);

      pri = pr - punt_reg_pool;

      if (0 == punt_reason_data[reason].pd_users++ &&
	  NULL != punt_reason_data[reason].pd_fn)
	punt_reason_data[reason].pd_fn (VLIB_ENABLE,
					punt_reason_data[reason].pd_data);

      punt_reg_add (pr);
    }

  /*
   * add this reg to the list the client has made
   */
  pr->pr_locks++;
  vec_add1 (pc->pc_regs, pri);

  punt_reg_mk_dp (reason);

  return 0;
}

int
vlib_punt_unregister (vlib_punt_hdl_t client,
		      vlib_punt_reason_t reason, const char *node_name)
{
  vlib_node_t *punt_to;
  punt_client_t *pc;
  vlib_main_t *vm;
  punt_reg_t *pr;
  u32 pri;

  if (reason >= punt_reason_last)
    return -1;

  vm = vlib_get_main ();
  pc = pool_elt_at_index (punt_client_pool, client);
  punt_to = vlib_get_node_by_name (vm, (u8 *) node_name);

  /*
   * construct a registration and check if it's one this client already has
   */
  pri = punt_reg_find (reason, punt_to->index);

  if (~0 != pri)
    {
      u32 pos;

      pos = vec_search (pc->pc_regs, pri);

      if (~0 == pos)
	{
	  /* not a registration for this client */
	  return -1;
	}
      vec_del1 (pc->pc_regs, pos);

      pr = pool_elt_at_index (punt_reg_pool, pri);

      pr->pr_locks--;

      if (0 == pr->pr_locks)
	{
	  if (0 == --punt_reason_data[reason].pd_users &&
	      NULL != punt_reason_data[reason].pd_fn)
	    punt_reason_data[reason].pd_fn (VLIB_DISABLE,
					    punt_reason_data[reason].pd_data);
	  punt_reg_remove (pr);
	  pool_put (punt_reg_pool, pr);
	}
    }

  /*
   * rebuild the DP data-base
   */
  punt_reg_mk_dp (reason);

  return (0);
}

int
vlib_punt_reason_validate (vlib_punt_reason_t reason)
{
  if (reason < punt_reason_last)
    return (0);

  return (-1);
}

u32
vlib_punt_reason_get_flags (vlib_punt_reason_t pr)
{
  return pr < punt_reason_last ? punt_reason_data[pr].flags : 0;
}

int
vlib_punt_reason_alloc (vlib_punt_hdl_t client, const char *reason_name,
			punt_interested_listener_t fn, void *data,
			vlib_punt_reason_t *reason, u32 flags,
			format_function_t *flags_format)
{
  vlib_punt_reason_t new;

  if (!punt_validate_client (client))
    return -2;

  new = punt_reason_last++;
  vec_validate (punt_reason_data, new);
  punt_reason_data[new].pd_name = format (NULL, "%s", reason_name);
  punt_reason_data[new].pd_reason = new;
  punt_reason_data[new].pd_fn = fn;
  punt_reason_data[new].pd_data = data;
  punt_reason_data[new].flags = flags;
  punt_reason_data[new].flags_format = flags_format;
  vec_add1 (punt_reason_data[new].pd_owners, client);

  vlib_validate_combined_counter (&punt_counters, new);
  vlib_zero_combined_counter (&punt_counters, new);

  *reason = new;

  /* build the DP data-base */
  punt_reg_mk_dp (*reason);

  return (0);
}

void
punt_reason_walk (punt_reason_walk_cb_t cb, void *ctx)
{
  punt_reason_data_t *pd;

  for (pd = punt_reason_data + 1; pd < vec_end (punt_reason_data); pd++)
    {
      cb (pd->pd_reason, pd->pd_name, ctx);
    }
}

/* Parse node name -> node index. */
uword
unformat_punt_client (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);

  return unformat_user (input, unformat_hash_vec_string,
			punt_client_db, result);
}

/* Parse punt reason */
uword
unformat_punt_reason (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
  u8 *s = 0;
  u8 found = 0;
  for (int i = 0; i < punt_reason_last - 1; i++)
    {
      punt_reason_data_t *pd = vec_elt_at_index (punt_reason_data, 1 + i);
      vec_reset_length (s);
      s = format (0, "%v%c", pd->pd_name, 0);
      if (unformat (input, (const char *) s))
	{
	  *result = pd->pd_reason;
	  found = 1;
	  break;
	}
    }
  vec_free (s);
  return found;
}

u8 *
format_punt_reg (u8 * s, va_list * args)
{
  u32 pri = va_arg (*args, u32);
  punt_reg_t *pr;

  pr = pool_elt_at_index (punt_reg_pool, pri);

  s = format (s, "%U -> %U",
	      format_vlib_punt_reason, pr->pr_reason,
	      format_vlib_node_name, vlib_get_main (), pr->pr_node_index);

  return (s);
}

u8 *
format_punt_reason_data (u8 * s, va_list * args)
{
  punt_reason_data_t *pd = va_arg (*args, punt_reason_data_t *);
  punt_client_t *pc;
  u32 *pci;
  if (pd->flags_format)
    s = format (s, "[%d] %v flags: %U from:[", pd->pd_reason, pd->pd_name,
		pd->flags_format, pd->flags);
  else
    s = format (s, "[%d] %v from:[", pd->pd_reason, pd->pd_name);
  vec_foreach (pci, pd->pd_owners)
  {
    pc = pool_elt_at_index (punt_client_pool, *pci);
    s = format (s, "%v ", pc->pc_name);
  }
  s = format (s, "]");

  return (s);
}

u8 *
format_punt_client (u8 * s, va_list * args)
{
  u32 pci = va_arg (*args, u32);
  punt_format_flags_t flags = va_arg (*args, punt_format_flags_t);
  punt_client_t *pc;

  pc = pool_elt_at_index (punt_client_pool, pci);

  s = format (s, "%v", pc->pc_name);

  if (flags & PUNT_FORMAT_FLAG_DETAIL)
    {
      punt_reason_data_t *pd;
      u32 *pri;

      s = format (s, "\n registrations:");
      vec_foreach (pri, pc->pc_regs)
      {
	s = format (s, "\n  [%U]", format_punt_reg, *pri);
      }

      s = format (s, "\n reasons:");

      vec_foreach (pd, punt_reason_data)
      {
	u32 *tmp;

	vec_foreach (tmp, pd->pd_owners)
	{
	  if (*tmp == pci)
	    s = format (s, "\n  %U", format_punt_reason_data, pd);
	}
      }
    }
  return (s);
}

static clib_error_t *
punt_client_show (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 pci = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_punt_client, &pci))
	;
      else
	break;
    }

  if (~0 != pci)
    {
      vlib_cli_output (vm, "%U", format_punt_client, pci,
		       PUNT_FORMAT_FLAG_DETAIL);
    }
  else
    {
      u8 *name;

      /* *INDENT-OFF* */
      hash_foreach(name, pci, punt_client_db,
        ({
          vlib_cli_output (vm, "%U", format_punt_client, pci,
                           PUNT_FORMAT_FLAG_NONE);
        }));
      /* *INDENT-ON* */
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_client_show_command, static) =
{
  .path = "show punt client",
  .short_help = "show client[s] registered with the punt infra",
  .function = punt_client_show,
};
/* *INDENT-ON* */

static clib_error_t *
punt_reason_show (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const punt_reason_data_t *pd;

  vec_foreach (pd, punt_reason_data)
  {
    vlib_cli_output (vm, "%U", format_punt_reason_data, pd);
  }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_reason_show_command, static) =
{
  .path = "show punt reasons",
  .short_help = "show all punt reasons",
  .function = punt_reason_show,
};
/* *INDENT-ON* */

static clib_error_t *
punt_db_show (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 pri, ii, jj;
  u64 key;

  /* *INDENT-OFF* */
  hash_foreach (key, pri, punt_reg_db,
    ({
      vlib_cli_output (vm, " %U", format_punt_reg, pri);
    }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "\nDerived data-plane data-base:");
  vlib_cli_output (vm,
		   "  (for each punt-reason the edge[s] from punt-dispatch)");

  vec_foreach_index (ii, punt_dp_db)
  {
    u8 *s = NULL;
    vlib_cli_output (vm, " %U", format_vlib_punt_reason, ii);

    vec_foreach_index (jj, punt_dp_db[ii])
    {
      s = format (s, "%d ", punt_dp_db[ii][jj]);
    }
    vlib_cli_output (vm, "   [%v]", s);
    vec_free (s);
  }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_db_show_command, static) =
{
  .path = "show punt db",
  .short_help = "show the punt DB",
  .function = punt_db_show,
};
/* *INDENT-ON* */

static clib_error_t *
punt_stats_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_combined_counter_main_t *cm = &punt_counters;
  vlib_counter_t c;
  u32 ii;

  for (ii = 0; ii < vlib_combined_counter_n_counters (cm); ii++)
    {
      vlib_get_combined_counter (cm, ii, &c);
      vlib_cli_output (vm, "%U packets:%lld bytes:%lld",
		       format_vlib_punt_reason, ii, c.packets, c.bytes);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_stats_show_command, static) =
{
  .path = "show punt stats",
  .short_help = "show the punt stats",
  .function = punt_stats_show,
};
/* *INDENT-ON* */

static clib_error_t *
punt_init (vlib_main_t * vm)
{
  punt_client_db = hash_create_vec (0, sizeof (u8), sizeof (u32));

  return (NULL);
}

VLIB_INIT_FUNCTION (punt_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
