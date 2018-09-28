/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/punt/punt.h>

/**
 * The last allocate punt reason
 */
static punt_reason_t punt_reason_last;

vlib_combined_counter_main_t punt_counters = {
  .name = "punt",
  .stat_segment_name = "/net/punt",
};

/**
 * A punt reason
 */
typedef struct punt_reason_data_t_
{
  u8 *pd_name;
  u8 *pd_default;
  u32 *pd_owners;
} punt_reason_data_t;

static punt_reason_data_t *punt_reason_data;

typedef enum punt_format_flags_t_
{
  PUNT_FORMAT_FLAG_NONE = 0,
  PUNT_FORMAT_FLAG_DETAIL = (1 << 0),
} punt_format_flags_t;

typedef struct punt_reg_t_
{
  punt_reason_t pr_reason;

  /* vector */
  u8 *pr_node_name;

  /* The edge to follow in the DP to get to the next node */
  u32 pr_edge;
} punt_reg_t;

static punt_reg_t *punt_reg_pool;

/**
 * A DB to keep track of the registered nodes per-reason
 */
u32 **punt_db;
u32 **punt_dp_db;

/**
 * A client using the punt serivce and its registrations
 */
typedef struct punt_client_t_
{
  u8 *pc_name;

  u32 *pc_regs;
} punt_client_t;

static punt_client_t *punt_client_pool;
static uword *punt_client_db;

u8 *
format_punt_reason (u8 * s, va_list * args)
{
  punt_reason_t pr = va_arg (*args, int);

  return (format (s, "%v", punt_reason_data[pr].pd_name));
}

static void
punt_db_resize (void)
{
  u32 index = punt_reason_last - 1;

  vec_validate (punt_db, index);
  vec_validate (punt_dp_db, index);
  vec_add1 (punt_dp_db[index], 0);

  vlib_validate_combined_counter (&punt_counters, index);
  vlib_zero_combined_counter (&punt_counters, index);
}

punt_hdl_t
punt_client_register (const char *who)
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
punt_reg_cmp (void *a1, void *a2)
{
  punt_reg_t *pr1, *pr2;
  u32 *pri1, *pri2;

  pri1 = a1;
  pri2 = a2;
  pr1 = pool_elt_at_index (punt_reg_pool, *pri1);
  pr2 = pool_elt_at_index (punt_reg_pool, *pri2);

  return ((pr1->pr_reason == pr2->pr_reason) &&
          (0 == vec_cmp (pr1->pr_node_name, pr2->pr_node_name)));
}

static void
punt_reg_free (punt_reg_t * pr)
{
  vec_free (pr->pr_node_name);
  pool_put (punt_reg_pool, pr);
}

punt_reason_t
punt_reason_alloc (punt_hdl_t client,
                   const char *reason_name,
                   const char *default_node)
{
  punt_reason_t new = punt_reason_last++;

  vec_validate (punt_reason_data, new);
  punt_reason_data[new].pd_name = format (NULL, "%s", reason_name);
  punt_reason_data[new].pd_default = format (NULL, "%s", default_node);
  vec_add1(punt_reason_data[new].pd_owners, client);

  punt_db_resize ();

  punt_register(client, new, default_node);

  return (new);
}

int
punt_register (punt_hdl_t client,
               punt_reason_t reason,
               const char *node_name)
{
  vlib_node_t *punt_to, *punt_from, *punt_default;
  punt_reason_data_t *pd;
  uword default_edge;
  punt_client_t *pc;
  vlib_main_t *vm;
  punt_reg_t *pr;
  u32 pri, pos;

  if (reason >= punt_reason_last)
    return -1;

  vm = vlib_get_main ();
  pc = pool_elt_at_index (punt_client_pool, client);
  pd = &punt_reason_data[reason];

  /*
   * construct a registration and check if it's one this client already has
   */
  pool_get (punt_reg_pool, pr);

  pr->pr_reason = reason;
  pr->pr_node_name = format (NULL, "%s", node_name);
  pri = pr - punt_reg_pool;

  pos = vec_search_with_function (pc->pc_regs, &pri, punt_reg_cmp);

  if (~0 != pos)
    {
      /* duplicate registration */
      punt_reg_free (pr);
      return -1;
    }
  vec_add1 (pc->pc_regs, pri);

  /*
   * get the graph node the user wants to punt to and from
   */
  punt_to = vlib_get_node_by_name (vm, (u8 *) node_name);
  punt_from = vlib_get_node_by_name (vm, (u8 *) "punt-dispatch");
  punt_default = vlib_get_node_by_name (vm, pd->pd_default);
  pr->pr_edge = vlib_node_add_next (vm, punt_from->index, punt_to->index);
  default_edge = vlib_node_add_next (vm, punt_from->index, punt_default->index);

  /*
   * add this entry to the DB and plugin the arc. we know it's a unique
   * arc, that was checked above.
   */
  vec_add1 (punt_db[reason], pri);

  if (punt_dp_db[reason][0] == default_edge ||
      punt_dp_db[reason][0] == 0)
    punt_dp_db[reason][0] = pr->pr_edge;
  else
    vec_add1 (punt_dp_db[reason], pr->pr_edge);

  return 0;
}

/* Parse node name -> node index. */
uword
unformat_punt_client (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);

  return unformat_user (input, unformat_hash_vec_string,
                        punt_client_db, result);
}

u8 *
format_punt_reg (u8 * s, va_list * args)
{
  u32 pri = va_arg (*args, u32);
  punt_reg_t *pr;

  pr = pool_elt_at_index (punt_reg_pool, pri);

  s = format (s, "%U -> %v",
              format_punt_reason, pr->pr_reason, pr->pr_node_name);

  return (s);
}

u8 *
format_punt_reason_data (u8 * s, va_list * args)
{
  punt_reason_data_t *pd = va_arg (*args, punt_reason_data_t*);
  punt_client_t *pc;
  u32 *pci;

  s = format (s, "%v default-node:%v from:[",
              pd->pd_name,
              pd->pd_default,
              s);
  vec_foreach(pci, pd->pd_owners)
    {
      pc = pool_elt_at_index(punt_client_pool, *pci);
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

          vec_foreach(tmp, pd->pd_owners)
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
                  unformat_input_t * input,
                  vlib_cli_command_t * cmd)
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
              unformat_input_t * input,
              vlib_cli_command_t * cmd)
{
  u32 *pri, ii, jj;

  vec_foreach_index (ii, punt_db)
  {
    vec_foreach (pri, punt_db[ii])
      {
        vlib_cli_output (vm, " %U", format_punt_reg, *pri);
      }
  }

  vec_foreach_index (ii, punt_dp_db)
    {
      u8 *s = NULL;
      vlib_cli_output (vm, " %U", format_punt_reason, ii);

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
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  vlib_combined_counter_main_t *cm = &punt_counters;
  vlib_counter_t c;
  u32 ii;

  for (ii = 0; ii < vlib_combined_counter_n_counters (cm); ii++)
    {
      vlib_get_combined_counter (cm, ii, &c);
      vlib_cli_output (vm, "%U packets:%lld bytes:%lld",
                       format_punt_reason, ii, c.packets, c.bytes);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_stats_show_command, static) =
{
  .path = "show punt state",
  .short_help = "show the punt stats",
  .function = punt_stats_show,
};
/* *INDENT-ON* */

static clib_error_t *
punt_init (vlib_main_t * vm)
{
  punt_hdl_t hdl;

  punt_client_db = hash_create_vec (0, sizeof (u8), sizeof (u32));

  /*
   * register the vnet client and make it the owner of all the specified reaons
   */
  hdl = punt_client_register ("vnet");

#define _(v, s, d) punt_reason_alloc(hdl,s,d);
  foreach_punt_reason
#undef _

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
