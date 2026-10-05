/* SPDX-License-Identifier: Apache-2.0 */

/*
 * floodguard.c — mighty_xddos Flood Guard (VPP mode) control plane.
 * virtserver drives it through vppctl (ddos/floodguard_vpp.go):
 *
 *   floodguard interface <interface> enable [arp <policer>] [broadcast <policer>]
 *                                         [ctrl <policer>] [multicast <policer>]
 *   floodguard interface <interface> disable
 *   floodguard victim add <ip4> syn|udp|icmp policer <policer> [port <n>]
 *   floodguard victim add <ip4> syn-challenge
 *   floodguard victim del <ip4> syn|udp|icmp|syn-challenge
 *   floodguard victim clear
 *   floodguard syn-challenge [whitelist-ttl <seconds>] [whitelist-size <n>]
 *   show floodguard [victims]
 *
 * "enable" replaces the interface's whole Broadcast Filter configuration
 * (a policer left out = that kind is not policed). The victim node is
 * always attached to an enabled interface (victim policing and the SYN
 * Reset Challenge); the storm nodes only while some Broadcast Filter
 * policer is set.
 */

#include <sys/random.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/format.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <floodguard/floodguard.h>

floodguard_main_t floodguard_main;

static const char *const floodguard_l2_kind_keywords[FLOODGUARD_N_L2_KIND] = {
  "arp", "broadcast", "ctrl", "multicast"
};

static const char *const floodguard_flood_keywords[FLOODGUARD_N_FLOOD] = {
  "syn", "udp", "icmp"
};

static const char *const floodguard_drop_counter_names[FLOODGUARD_N_KIND] = {
  [FLOODGUARD_KIND_NONE] = "none",
  [FLOODGUARD_KIND_ARP] = "arp",
  [FLOODGUARD_KIND_BROADCAST] = "broadcast",
  [FLOODGUARD_KIND_CTRL] = "l2-control",
  [FLOODGUARD_KIND_MULTICAST] = "multicast",
  [FLOODGUARD_KIND_SYN] = "syn",
  [FLOODGUARD_KIND_UDP] = "udp",
  [FLOODGUARD_KIND_ICMP] = "icmp",
  [FLOODGUARD_KIND_SYN_CHALLENGE] = "syn-challenge",
};

static const char *const floodguard_drop_stat_names[FLOODGUARD_N_KIND] = {
  [FLOODGUARD_KIND_NONE] = "/floodguard/drops/none",
  [FLOODGUARD_KIND_ARP] = "/floodguard/drops/arp",
  [FLOODGUARD_KIND_BROADCAST] = "/floodguard/drops/broadcast",
  [FLOODGUARD_KIND_CTRL] = "/floodguard/drops/l2-control",
  [FLOODGUARD_KIND_MULTICAST] = "/floodguard/drops/multicast",
  [FLOODGUARD_KIND_SYN] = "/floodguard/drops/syn",
  [FLOODGUARD_KIND_UDP] = "/floodguard/drops/udp",
  [FLOODGUARD_KIND_ICMP] = "/floodguard/drops/icmp",
  [FLOODGUARD_KIND_SYN_CHALLENGE] = "/floodguard/drops/syn-challenge",
};

static const char *const
  floodguard_challenge_counter_names[FLOODGUARD_N_CHALLENGE_COUNTER] = {
    [FLOODGUARD_CHALLENGE_CHALLENGED] = "challenged",
    [FLOODGUARD_CHALLENGE_VERIFIED] = "verified",
    [FLOODGUARD_CHALLENGE_PERMITTED] = "permitted",
    [FLOODGUARD_CHALLENGE_WHITELIST_FULL] = "whitelist-full",
    [FLOODGUARD_CHALLENGE_SWEPT_WHITELIST] = "swept-whitelist",
  };

static const char *const
  floodguard_challenge_stat_names[FLOODGUARD_N_CHALLENGE_COUNTER] = {
    [FLOODGUARD_CHALLENGE_CHALLENGED] = "/floodguard/challenge/challenged",
    [FLOODGUARD_CHALLENGE_VERIFIED] = "/floodguard/challenge/verified",
    [FLOODGUARD_CHALLENGE_PERMITTED] = "/floodguard/challenge/permitted",
    [FLOODGUARD_CHALLENGE_WHITELIST_FULL] =
      "/floodguard/challenge/whitelist-full",
    [FLOODGUARD_CHALLENGE_SWEPT_WHITELIST] =
      "/floodguard/challenge/swept-whitelist",
  };

static u64
floodguard_challenge_count (floodguard_main_t *fm,
			    floodguard_challenge_counter_t c)
{
  return vlib_get_simple_counter (&fm->challenge_counters[c], 0);
}

/* floodguard_whitelist_buckets: one bucket per two whitelist entries. */
static u32
floodguard_whitelist_buckets (u32 max_entries)
{
  return max_entries / 2;
}

/* floodguard_challenge_tables: create the SYN Reset Challenge whitelist on
 * the first challenge victim, sized for challenge_whitelist_max. Main
 * thread, with the workers stopped (CLI barrier): the victim node only
 * reads it once a challenge victim exists, which is armed after this
 * returns. */
static void
floodguard_challenge_tables (floodguard_main_t *fm)
{
  if (fm->challenge_tables_ready)
    return;
  fm->challenge_whitelist_buckets =
    floodguard_whitelist_buckets (fm->challenge_whitelist_max);
  clib_bihash_init_8_8 (&fm->challenge_whitelist,
			"floodguard challenge whitelist",
			fm->challenge_whitelist_buckets, 0);
  fm->n_whitelist = 0;
  fm->challenge_tables_ready = 1;
}

/* floodguard_policer_main: the policer plugin's state, resolved once
 * through its exported accessors (plugins load in any order, so not at
 * init time). */
static policer_main_t *
floodguard_policer_main (floodguard_main_t *fm)
{
  if (!fm->pm)
    {
      fm->policer_counters = policer_get_counters ();
      fm->pm = fm->policer_counters ? policer_get_main () : 0;
    }
  return fm->pm;
}

/* floodguard_policer_index: policer name -> index, or an error. */
static clib_error_t *
floodguard_policer_index (floodguard_main_t *fm, u8 *name, u32 *index)
{
  policer_main_t *pm = floodguard_policer_main (fm);
  uword *p;

  if (!pm)
    return clib_error_return (0, "policer plugin not loaded");
  vec_add1 (name, 0);
  p = hash_get_mem (pm->policer_index_by_name, name);
  if (!p)
    {
      clib_error_t *e = clib_error_return (0, "policer '%s' not found", name);
      vec_free (name);
      return e;
    }
  vec_free (name);
  *index = p[0];
  return 0;
}

static void
floodguard_set_arcs (floodguard_if_t *ifc, u32 sw_if_index, u8 want)
{
  static const struct
  {
    u8 bit;
    const char *arc;
    const char *node;
  } arcs[] = {
    { FLOODGUARD_ARC_STORM_IP4, "l2-input-ip4", "floodguard-l2-ip4" },
    { FLOODGUARD_ARC_STORM_IP6, "l2-input-ip6", "floodguard-l2-ip6" },
    { FLOODGUARD_ARC_STORM_NONIP, "l2-input-nonip", "floodguard-l2-nonip" },
    { FLOODGUARD_ARC_VICTIM, "l2-input-ip4", "floodguard-victim" },
  };
  int i;

  for (i = 0; i < ARRAY_LEN (arcs); i++)
    {
      int on = (want & arcs[i].bit) != 0;
      if (on == ((ifc->arcs & arcs[i].bit) != 0))
	continue;
      vnet_l2_feature_enable_disable (arcs[i].arc, arcs[i].node, sw_if_index,
				      on, 0, 0);
    }
  ifc->arcs = want;
}

static clib_error_t *
floodguard_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0, policer[FLOODGUARD_N_L2_KIND];
  int enable = -1, any = 0, i;
  clib_error_t *error = 0;
  u8 *name = 0;

  for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
    policer[i] = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int matched = 0;
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	{
	  for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
	    if (unformat (input, floodguard_l2_kind_keywords[i]))
	      {
		if (!unformat (input, "%s", &name))
		  return clib_error_return (0, "%s: policer name expected",
					    floodguard_l2_kind_keywords[i]);
		if ((error = floodguard_policer_index (fm, name, &policer[i])))
		  return error;
		name = 0;
		any = 1;
		matched = 1;
		break;
	      }
	  if (!matched)
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, input);
	}
    }
  if (sw_if_index == ~0 || enable < 0)
    return clib_error_return (0, "specify an interface and enable|disable");

  floodguard_if_t empty = { .policer = { ~0, ~0, ~0, ~0 } };
  vec_validate_init_empty (fm->ifs, sw_if_index, empty);
  floodguard_if_t *ifc = vec_elt_at_index (fm->ifs, sw_if_index);
  if (!enable)
    {
      floodguard_set_arcs (ifc, sw_if_index, 0);
      for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
	ifc->policer[i] = ~0;
      return 0;
    }
  for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
    ifc->policer[i] = policer[i];
  floodguard_set_arcs (ifc, sw_if_index,
		       FLOODGUARD_ARC_VICTIM |
			 (any ? FLOODGUARD_ARC_STORM_IP4 |
				  FLOODGUARD_ARC_STORM_IP6 |
				  FLOODGUARD_ARC_STORM_NONIP :
				0));
  return 0;
}

static clib_error_t *
floodguard_victim_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  ip4_address_t addr;
  int is_add = -1, clear = 0, type = -1, i;
  u32 port = 0, pi = ~0;
  u8 *name = 0;
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add %U", unformat_ip4_address, &addr))
	is_add = 1;
      else if (unformat (input, "del %U", unformat_ip4_address, &addr))
	is_add = 0;
      else if (unformat (input, "clear"))
	clear = 1;
      else if (unformat (input, "policer %s", &name))
	{
	  if ((error = floodguard_policer_index (fm, name, &pi)))
	    return error;
	  name = 0;
	}
      else if (unformat (input, "syn-challenge"))
	type = FLOODGUARD_N_FLOOD;
      else if (unformat (input, "port %u", &port))
	{
	  if (port > 65535)
	    return clib_error_return (0, "port out of range");
	}
      else
	{
	  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
	    if (unformat (input, floodguard_flood_keywords[i]))
	      {
		type = i;
		break;
	      }
	  if (i == FLOODGUARD_N_FLOOD)
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, input);
	}
    }

  if (clear)
    {
      clib_bihash_free_8_8 (&fm->victims);
      clib_bihash_init_8_8 (&fm->victims, "floodguard victims",
			    FLOODGUARD_VICTIM_BUCKETS,
			    FLOODGUARD_VICTIM_MEMORY);
      fm->n_victims = 0;
      return 0;
    }
  if (is_add < 0 || type < 0)
    return clib_error_return (
      0, "specify add|del <ip4> and syn|udp|icmp|syn-challenge");
  if (type == FLOODGUARD_N_FLOOD)
    {
      if (pi != ~0 || port)
	return clib_error_return (0, "syn-challenge takes no policer or port");
      if (is_add)
	floodguard_challenge_tables (fm);
    }
  else if (is_add && pi == ~0)
    return clib_error_return (0, "specify policer <name>");
  if (port && type == FLOODGUARD_N_FLOOD - 1)
    return clib_error_return (0, "icmp has no port");

  clib_bihash_kv_8_8_t kv, val;
  kv.key = addr.as_u32;
  int exists = clib_bihash_search_8_8 (&fm->victims, &kv, &val) == 0;
  u64 v = exists ? val.value : 0;

  switch (type)
    {
    case 0:
      v &= ~(FLOODGUARD_V_SYN | (0xffffULL << 16));
      if (is_add)
	v |= FLOODGUARD_V_SYN | ((u64) port << 16);
      break;
    case 1:
      v &= ~(FLOODGUARD_V_UDP | 0xffffULL);
      if (is_add)
	v |= FLOODGUARD_V_UDP | port;
      break;
    case 2:
      v &= ~FLOODGUARD_V_ICMP;
      if (is_add)
	v |= FLOODGUARD_V_ICMP;
      break;
    default:
      v &= ~FLOODGUARD_V_SYN_CHALLENGE;
      if (is_add)
	v |= FLOODGUARD_V_SYN_CHALLENGE;
    }
  if (is_add && type < FLOODGUARD_N_FLOOD)
    fm->flood_policer[type] = pi;

  if (v & FLOODGUARD_V_ANY)
    {
      kv.value = v;
      if (clib_bihash_add_del_8_8 (&fm->victims, &kv, 1))
	return clib_error_return (0, "victim table full");
      if (!exists)
	fm->n_victims++;
    }
  else if (exists)
    {
      clib_bihash_add_del_8_8 (&fm->victims, &kv, 0);
      fm->n_victims--;
    }
  return 0;
}

static u8 *
format_floodguard_policer (u8 *s, va_list *args)
{
  floodguard_main_t *fm = va_arg (*args, floodguard_main_t *);
  u32 pi = va_arg (*args, u32);

  if (pi == ~0)
    return format (s, "-");
  if (!fm->pm || pool_is_free_index (fm->pm->policers, pi))
    return format (s, "%u (invalid)", pi);
  return format (s, "%s", pool_elt_at_index (fm->pm->policers, pi)->name);
}

typedef struct
{
  vlib_main_t *vm;
  u32 n;
} floodguard_show_ctx_t;

static int
floodguard_show_victim (clib_bihash_kv_8_8_t *kv, void *arg)
{
  floodguard_show_ctx_t *ctx = arg;
  ip4_address_t addr = { .as_u32 = (u32) kv->key };
  u64 v = kv->value;
  u8 *s = format (0, "  %U:", format_ip4_address, &addr);

  if (v & FLOODGUARD_V_SYN)
    s = FLOODGUARD_V_SYN_PORT (v) ?
	  format (s, " syn port %u", FLOODGUARD_V_SYN_PORT (v)) :
	  format (s, " syn");
  if (v & FLOODGUARD_V_UDP)
    s = FLOODGUARD_V_UDP_PORT (v) ?
	  format (s, " udp port %u", FLOODGUARD_V_UDP_PORT (v)) :
	  format (s, " udp");
  if (v & FLOODGUARD_V_ICMP)
    s = format (s, " icmp");
  if (v & FLOODGUARD_V_SYN_CHALLENGE)
    s = format (s, " syn-challenge");
  vlib_cli_output (ctx->vm, "%v", s);
  vec_free (s);
  ctx->n++;
  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
show_floodguard_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  vnet_main_t *vnm = vnet_get_main ();
  int victims = unformat (input, "victims");
  u32 sw_if_index;
  int i;

  floodguard_policer_main (fm);
  if (victims)
    {
      floodguard_show_ctx_t ctx = { .vm = vm };
      clib_bihash_foreach_key_value_pair_8_8 (&fm->victims,
					      floodguard_show_victim, &ctx);
      vlib_cli_output (vm, "Victims: %u", ctx.n);
      return 0;
    }

  vlib_cli_output (vm, "Flood Guard:");
  vlib_cli_output (vm, "  Interfaces:");
  vec_foreach_index (sw_if_index, fm->ifs)
    {
      floodguard_if_t *ifc = vec_elt_at_index (fm->ifs, sw_if_index);
      if (!ifc->arcs)
	continue;
      vlib_cli_output (vm,
		       "    %U: arp %U, broadcast %U, ctrl %U, multicast %U",
		       format_vnet_sw_if_index_name, vnm, sw_if_index,
		       format_floodguard_policer, fm, ifc->policer[0],
		       format_floodguard_policer, fm, ifc->policer[1],
		       format_floodguard_policer, fm, ifc->policer[2],
		       format_floodguard_policer, fm, ifc->policer[3]);
    }
  vlib_cli_output (vm, "  Victims: %u (syn %U, udp %U, icmp %U)",
		   fm->n_victims, format_floodguard_policer, fm,
		   fm->flood_policer[0], format_floodguard_policer, fm,
		   fm->flood_policer[1], format_floodguard_policer, fm,
		   fm->flood_policer[2]);
  vlib_cli_output (vm, "  Drops:");
  for (i = FLOODGUARD_KIND_ARP; i < FLOODGUARD_N_KIND; i++)
    vlib_cli_output (vm, "    %-13s %llu", floodguard_drop_counter_names[i],
		     vlib_get_simple_counter (&fm->drop_counters[i], 0));
  /* virtserver parses these labels (ddos/floodguard_vpp.go). */
  vlib_cli_output (vm, "  SYN Reset Challenge:");
  vlib_cli_output (vm, "    Whitelist TTL:     %us",
		   fm->challenge_whitelist_ttl_sec);
  vlib_cli_output (
    vm, "    Challenged (SYN-ACK reflected): %llu",
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_CHALLENGED));
  vlib_cli_output (
    vm, "    Verified (RST matched):         %llu",
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_VERIFIED));
  vlib_cli_output (
    vm, "    Permitted (already verified):   %llu",
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_PERMITTED));
  vlib_cli_output (
    vm,
    "    Whitelist:                      %u/%u (refused at cap %llu, "
    "expired %llu)",
    fm->n_whitelist, fm->challenge_whitelist_max,
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_WHITELIST_FULL),
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_SWEPT_WHITELIST));
  if (!fm->cookie_key_ready)
    vlib_cli_output (vm, "    Disabled: no cookie key (see VPP log)");
  return 0;
}

static clib_error_t *
floodguard_challenge_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  u32 ttl = 0, size = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "whitelist-ttl %u", &ttl))
	{
	  if (ttl == 0)
	    return clib_error_return (0, "whitelist-ttl must be > 0");
	}
      else if (unformat (input, "whitelist-size %u", &size))
	{
	  if (size < FLOODGUARD_CHALLENGE_WHITELIST_MIN ||
	      size > FLOODGUARD_CHALLENGE_WHITELIST_MAX)
	    return clib_error_return (0, "whitelist-size must be %u-%u",
				      FLOODGUARD_CHALLENGE_WHITELIST_MIN,
				      FLOODGUARD_CHALLENGE_WHITELIST_MAX);
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (!ttl && !size)
    return clib_error_return (
      0, "specify whitelist-ttl <seconds> and/or whitelist-size <n>");
  if (ttl)
    fm->challenge_whitelist_ttl_sec = ttl;
  if (size && size != fm->challenge_whitelist_max)
    {
      fm->challenge_whitelist_max = size;
      /* An existing table keeps its entries while its bucket count still
       * fits the new size; otherwise it is rebuilt and the verified
       * clients are challenged once more. Workers are stopped (CLI
       * barrier). */
      if (fm->challenge_tables_ready &&
	  floodguard_whitelist_buckets (size) !=
	    fm->challenge_whitelist_buckets)
	{
	  clib_bihash_free_8_8 (&fm->challenge_whitelist);
	  fm->challenge_tables_ready = 0;
	  floodguard_challenge_tables (fm);
	}
    }
  return 0;
}

/* floodguard_challenge_sweep_whitelist: drop expired entries — a bihash
 * never evicts on its own. Walked bucket by bucket with a time budget,
 * like l2fib_scan. */
static void
floodguard_challenge_sweep_whitelist (vlib_main_t *vm, floodguard_main_t *fm)
{
  clib_bihash_8_8_t *h = &fm->challenge_whitelist;
  u64 now = (u64) vlib_time_now (vm);
  f64 last_start = vlib_time_now (vm);
  u32 n_swept = 0, i, j, k;

  for (i = 0; i < h->nbuckets; i++)
    {
      if (vlib_time_now (vm) - last_start > 20e-6)
	{
	  vlib_process_suspend (vm, 100e-6);
	  last_start = vlib_time_now (vm);
	}
      clib_bihash_bucket_8_8_t *b = clib_bihash_get_bucket_8_8 (h, i);
      if (clib_bihash_bucket_is_empty_8_8 (b))
	continue;
      clib_bihash_value_8_8_t *v = clib_bihash_get_value_8_8 (h, b->offset);
      for (j = 0; j < (1U << b->log2_pages); j++, v++)
	for (k = 0; k < 7 /* bihash_8_8 KVP per page */; k++)
	  {
	    if (clib_bihash_is_free_8_8 (&v->kvp[k]) ||
		now < v->kvp[k].value)
	      continue;
	    clib_bihash_kv_8_8_t kv = v->kvp[k];
	    if (clib_bihash_add_del_8_8 (h, &kv, 0) == 0)
	      {
	        clib_atomic_fetch_sub (&fm->n_whitelist, 1);
	        n_swept++;
	      }
	    if (clib_bihash_bucket_is_empty_8_8 (b))
	      goto next_bucket;
	  }
    next_bucket:;
    }
  if (n_swept)
    vlib_increment_simple_counter (
      &fm->challenge_counters[FLOODGUARD_CHALLENGE_SWEPT_WHITELIST],
      vm->thread_index, 0, n_swept);
}

/* floodguard_challenge_sweep_process: once a second, walk the whitelist
 * only while it holds entries, so an idle box pays nothing. */
static uword
floodguard_challenge_sweep_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
				    vlib_frame_t *f)
{
  floodguard_main_t *fm = &floodguard_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_process_get_events (vm, 0);
      if (fm->challenge_tables_ready && fm->n_whitelist)
	floodguard_challenge_sweep_whitelist (vm, fm);
    }
  return 0;
}

VLIB_REGISTER_NODE (floodguard_challenge_sweep_node, static) = {
  .function = floodguard_challenge_sweep_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "floodguard-challenge-sweep",
};


VLIB_CLI_COMMAND (floodguard_interface_command, static) = {
  .path = "floodguard interface",
  .short_help = "floodguard interface <interface> enable [arp <policer>] "
		"[broadcast <policer>] [ctrl <policer>] [multicast <policer>] "
		"| floodguard interface <interface> disable",
  .function = floodguard_interface_command_fn,
};

VLIB_CLI_COMMAND (floodguard_victim_command, static) = {
  .path = "floodguard victim",
  .short_help = "floodguard victim add <ip4> syn|udp|icmp policer <policer> "
		"[port <n>] | floodguard victim add <ip4> syn-challenge | "
		"floodguard victim del <ip4> syn|udp|icmp|syn-challenge | "
		"floodguard victim clear",
  .function = floodguard_victim_command_fn,
};

VLIB_CLI_COMMAND (floodguard_challenge_command, static) = {
  .path = "floodguard syn-challenge",
  .short_help = "floodguard syn-challenge [whitelist-ttl <seconds>] "
		"[whitelist-size <n>]",
  .function = floodguard_challenge_command_fn,
};

VLIB_CLI_COMMAND (show_floodguard_command, static) = {
  .path = "show floodguard",
  .short_help = "show floodguard [victims]",
  .function = show_floodguard_command_fn,
};

static clib_error_t *
floodguard_init (vlib_main_t *vm)
{
  floodguard_main_t *fm = &floodguard_main;
  int i;

  fm->vlib_main = vm;
  fm->vnet_main = vnet_get_main ();
  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
    fm->flood_policer[i] = ~0;
  clib_bihash_init_8_8 (&fm->victims, "floodguard victims",
			FLOODGUARD_VICTIM_BUCKETS, FLOODGUARD_VICTIM_MEMORY);
  for (i = 0; i < FLOODGUARD_N_KIND; i++)
    {
      fm->drop_counters[i].name = (char *) floodguard_drop_counter_names[i];
      fm->drop_counters[i].stat_segment_name =
	(char *) floodguard_drop_stat_names[i];
      vlib_validate_simple_counter (&fm->drop_counters[i], 0);
      vlib_zero_simple_counter (&fm->drop_counters[i], 0);
    }
  for (i = 0; i < FLOODGUARD_N_CHALLENGE_COUNTER; i++)
    {
      fm->challenge_counters[i].name =
	(char *) floodguard_challenge_counter_names[i];
      fm->challenge_counters[i].stat_segment_name =
	(char *) floodguard_challenge_stat_names[i];
      vlib_validate_simple_counter (&fm->challenge_counters[i], 0);
      vlib_zero_simple_counter (&fm->challenge_counters[i], 0);
    }
  fm->challenge_whitelist_ttl_sec =
    FLOODGUARD_CHALLENGE_DEFAULT_WHITELIST_TTL_SEC;
  fm->challenge_whitelist_max = FLOODGUARD_CHALLENGE_DEFAULT_WHITELIST_MAX;

  /* The challenge cookie key: a fresh random secret every start, never
   * shown. Without it the challenge is off (SYNs pass untouched) rather
   * than VPP failing to start. */
  {
    u8 *k = (u8 *) fm->cookie_key;
    size_t got = 0;
    while (got < sizeof (fm->cookie_key))
      {
	ssize_t n = getrandom (k + got, sizeof (fm->cookie_key) - got, 0);
	if (n < 0)
	  {
	    if (errno == EINTR)
	      continue;
	    break;
	  }
	got += n;
      }
    fm->cookie_key_ready = got == sizeof (fm->cookie_key) &&
			   (fm->cookie_key[0] | fm->cookie_key[1]) != 0;
    if (!fm->cookie_key_ready)
      clib_warning ("floodguard: SYN Reset Challenge key not set (%s) - "
		    "challenge disabled, SYNs are forwarded",
		    strerror (errno));
  }
  return 0;
}

VLIB_INIT_FUNCTION (floodguard_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "mighty_xddos Flood Guard (storm, flood and SYN challenge)",
};
