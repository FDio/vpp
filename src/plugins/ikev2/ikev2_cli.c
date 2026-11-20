/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include <ctype.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/interface/cli_types.h>
#include <vnet/ip/cli_types.h>
#include <plugins/ikev2/ikev2.h>
#include <plugins/ikev2/ikev2_priv.h>

u8 *
format_ikev2_id_type_and_data (u8 * s, va_list * args)
{
  ikev2_id_t *id = va_arg (*args, ikev2_id_t *);

  if (id->type == 0 || vec_len (id->data) == 0)
    return format (s, "none");

  s = format (s, "id-type %U data ", format_ikev2_id_type, id->type);

  switch (id->type)
    {
    case IKEV2_ID_TYPE_ID_IPV4_ADDR:
      s = format (s, "%U", format_ip4_address, id->data);
      break;
    case IKEV2_ID_TYPE_ID_IPV6_ADDR:
      s = format (s, "%U", format_ip6_address, id->data);
      break;
    case IKEV2_ID_TYPE_ID_FQDN:	/* fallthrough */
    case IKEV2_ID_TYPE_ID_RFC822_ADDR:
      s = format (s, "%v", id->data);
      break;
    default:
      s = format (s, "0x%U", format_hex_bytes, &id->data,
		  (uword) (vec_len (id->data)));
      break;
    }

  return s;
}

static u8 *
format_ikev2_traffic_selector (u8 * s, va_list * va)
{
  ikev2_ts_t *ts = va_arg (*va, ikev2_ts_t *);
  u32 index = va_arg (*va, u32);

  s = format (s, "%u type %u protocol_id %u addr "
	      "%U - %U port %u - %u\n",
	      index, ts->ts_type, ts->protocol_id,
	      format_ip_address, &ts->start_addr,
	      format_ip_address, &ts->end_addr,
	      clib_net_to_host_u16 (ts->start_port),
	      clib_net_to_host_u16 (ts->end_port));
  return s;
}

static u8 *
format_ikev2_child_sa (u8 * s, va_list * va)
{
  ikev2_child_sa_t *child = va_arg (*va, ikev2_child_sa_t *);
  u32 index = va_arg (*va, u32);
  ikev2_ts_t *ts;
  ikev2_sa_transform_t *tr;
  u8 *c = 0;
  vlib_main_t *vm = vlib_get_main ();

  u32 indent = format_get_indent (s);
  indent += 1;

  s = format (s, "child sa %u:", index);

  s = format (s, "\n    uptime: %f (s)\n    ",
	      vlib_time_now (vm) - child->timestamp);

  tr = ikev2_sa_get_td_for_type (child->r_proposals,
				 IKEV2_TRANSFORM_TYPE_ENCR);
  c = format (c, "%U ", format_ikev2_sa_transform, tr);

  tr = ikev2_sa_get_td_for_type (child->r_proposals,
				 IKEV2_TRANSFORM_TYPE_INTEG);
  c = format (c, "%U ", format_ikev2_sa_transform, tr);

  tr = ikev2_sa_get_td_for_type (child->r_proposals,
				 IKEV2_TRANSFORM_TYPE_ESN);
  c = format (c, "%U ", format_ikev2_sa_transform, tr);

  s = format (s, "%v\n", c);
  vec_free (c);

  s = format (s, "%Uspi(i) %lx spi(r) %lx\n", format_white_space, indent,
	      child->i_proposals ? child->i_proposals[0].spi : 0,
	      child->r_proposals ? child->r_proposals[0].spi : 0);

  s = format (s, "%USK_e  i:%U\n%Ur:%U\n",
	      format_white_space, indent,
	      format_hex_bytes, child->sk_ei, vec_len (child->sk_ei),
	      format_white_space, indent + 6,
	      format_hex_bytes, child->sk_er, vec_len (child->sk_er));
  if (child->sk_ai)
    {
      s = format (s, "%USK_a  i:%U\n%Ur:%U\n",
		  format_white_space, indent,
		  format_hex_bytes, child->sk_ai, vec_len (child->sk_ai),
		  format_white_space, indent + 6,
		  format_hex_bytes, child->sk_ar, vec_len (child->sk_ar));
    }
  s = format (s, "%Utraffic selectors (i):", format_white_space, indent);
  vec_foreach (ts, child->tsi)
    s = format (s, "%U", format_ikev2_traffic_selector, ts, ts - child->tsi);
  s = format (s, "%Utraffic selectors (r):", format_white_space, indent);
  vec_foreach (ts, child->tsr)
    s = format (s, "%U", format_ikev2_traffic_selector, ts, ts - child->tsr);
  return s;
}

static char *stateNames[] = {
#define _(v, f, s) s,
  foreach_ikev2_state
#undef _
};

static u8 *
format_ikev2_sa (u8 * s, va_list * va)
{
  ikev2_sa_t *sa = va_arg (*va, ikev2_sa_t *);
  int details = va_arg (*va, int);
  ikev2_sa_transform_t *tr;
  ikev2_child_sa_t *child;
  u32 indent = 1;
  vlib_main_t *vm = vlib_get_main ();

  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;

  s = format (s, "iip %U ispi %lx rip %U rspi %lx",
	      format_ip_address, &sa->iaddr, sa->ispi,
	      format_ip_address, &sa->raddr, sa->rspi);
  if (!details)
    return s;

  s = format (s, "\n%U", format_white_space, indent);

  tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  s = format (s, "%U ", format_ikev2_sa_transform, tr);

  tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  s = format (s, "%U ", format_ikev2_sa_transform, tr);

  tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);
  s = format (s, "%U ", format_ikev2_sa_transform, tr);

  tr = ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_DH);
  s = format (s, "%U", format_ikev2_sa_transform, tr);

  /* Responder SAs have no profile until IKE_AUTH matches the peer identity. */
  if (pool_is_free_index (km->profiles, sa->profile_index))
    s = format (s, "\n profile: none");
  else
    {
      p = pool_elt_at_index (km->profiles, sa->profile_index);
      s = format (s, "\n profile: %v", p->name);
    }

  if (sa->state <= IKEV2_STATE_NO_PROPOSAL_CHOSEN)
    {
      s = format (s, "\n state: %s", stateNames[sa->state]);
    }

  s =
    format (s, "\n uptime: %f (s)\n", vlib_time_now (vm) - sa->auth_timestamp);

  s = format (s, "\n%U", format_white_space, indent);

  s = format (s, "nonce i:%U\n%Ur:%U\n",
	      format_hex_bytes, sa->i_nonce, vec_len (sa->i_nonce),
	      format_white_space, indent + 6,
	      format_hex_bytes, sa->r_nonce, vec_len (sa->r_nonce));

  s = format (s, "%USK_d    %U\n", format_white_space, indent,
	      format_hex_bytes, sa->sk_d, vec_len (sa->sk_d));
  if (sa->sk_ai)
    {
      s = format (s, "%USK_a  i:%U\n%Ur:%U\n",
		  format_white_space, indent,
		  format_hex_bytes, sa->sk_ai, vec_len (sa->sk_ai),
		  format_white_space, indent + 6,
		  format_hex_bytes, sa->sk_ar, vec_len (sa->sk_ar));
    }
  s = format (s, "%USK_e  i:%U\n%Ur:%U\n",
	      format_white_space, indent,
	      format_hex_bytes, sa->sk_ei, vec_len (sa->sk_ei),
	      format_white_space, indent + 6,
	      format_hex_bytes, sa->sk_er, vec_len (sa->sk_er));
  s = format (s, "%USK_p  i:%U\n%Ur:%U\n",
	      format_white_space, indent,
	      format_hex_bytes, sa->sk_pi, vec_len (sa->sk_pi),
	      format_white_space, indent + 6,
	      format_hex_bytes, sa->sk_pr, vec_len (sa->sk_pr));

  s = format (s, "%Uidentifier (i) %U\n",
	      format_white_space, indent,
	      format_ikev2_id_type_and_data, &sa->i_id);
  s = format (s, "%Uidentifier (r) %U\n",
	      format_white_space, indent,
	      format_ikev2_id_type_and_data, &sa->r_id);

  vec_foreach (child, sa->childs)
  {
    s = format (s, "%U%U", format_white_space, indent + 2,
		format_ikev2_child_sa, child, child - sa->childs);
  }

  s = format (s, "Stats:\n");
  s = format (s, " keepalives :%u\n", sa->stats.n_keepalives);
  s = format (s, " rekey :%u\n", sa->stats.n_rekey_req);
  s = format (s, " SA init :%u (retransmit: %u)\n", sa->stats.n_sa_init_req,
	      sa->stats.n_init_retransmit);
  s = format (s, " retransmit: %u\n", sa->stats.n_retransmit);
  s = format (s, " SA auth :%u\n", sa->stats.n_sa_auth_req);

  return s;
}

static u8 *
parse_ikev2_name (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  if (vec_len (tok) == 0)
    return format (0, "missing profile name");

  for (u32 i = 0; i < vec_len (tok); i++)
    if (!(isalnum (tok[i]) || tok[i] == '_'))
      return format (0, "'%v' is not a profile name, only letters, digits and '_' are allowed",
		     tok);

  v->str = vec_dup (tok);
  return 0;
}

CLIB_CLI_TYPE (cli_type_ikev2_name, static) = {
  .name = "name",
  .help = "profile name, letters, digits and '_'",
  .owns_str = 1,
  .parse = parse_ikev2_name,
};

static void
complete_ikev2_profile (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;

  pool_foreach (p, km->profiles)
    {
      u8 *name = format (0, "%v%c", p->name, 0);

      if (cli_prefix_match ((char *) name, prefix))
	cli_candidate_add (out, (char *) name, 0);
      vec_free (name);
    }
}

CLIB_CLI_TYPE (cli_type_ikev2_profile, static) = {
  .name = "profile",
  .help = "name of an IKEv2 profile",
  .owns_str = 1,
  .parse = parse_ikev2_name,
  .complete = complete_ikev2_profile,
};

/* Hex number without 0x prefix, as shown by "show ikev2 sa" */
static u8 *
parse_ikev2_spi (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u64 val = 0;

  if (vec_len (tok) == 0 || vec_len (tok) > 16)
    return format (0, "'%v' is not a hex number of up to 64 bits", tok);

  for (u32 i = 0; i < vec_len (tok); i++)
    {
      u8 c = cli_to_lower (tok[i]);

      if (cli_is_digit (c))
	val = val << 4 | (c - '0');
      else if (c >= 'a' && c <= 'f')
	val = val << 4 | (c - 'a' + 10);
      else
	return format (0, "'%v' is not a hex number", tok);
    }

  if (a->max && val > a->max)
    return format (0, "'%v' is larger than %llx", tok, a->max);

  v->u64 = val;
  return 0;
}

CLIB_CLI_TYPE (cli_type_ikev2_spi, static) = {
  .name = "spi",
  .help = "hex number, e.g. 11223344",
  .parse = parse_ikev2_spi,
};

static clib_error_t *
show_ikev2_sa_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ikev2_main_t *km = &ikev2_main;
  cli_value_t *v = cli_get (ctx, "rspi");
  ikev2_sa_t *sa;
  u8 *s = 0;
  int details = cli_flag (ctx, "details");

  pool_foreach (sa, km->sas)
    {
      if (v)
	{
	  if (sa->rspi == v->u64)
	    {
	      s = format (s, "%U\n", format_ikev2_sa, sa, 1);
	      break;
	    }
	}
      else
	s = format (s, "%U\n", format_ikev2_sa, sa, details);
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

VLIB_CLI_COMMAND (show_ikev2_sa_command, static) = {
  .path = "show ikev2 sa",
  .short_help = "Show the IKEv2 security associations",
  .args = CLI_ARGS (CLI_OPT_KEYWORD ("rspi", cli_type_ikev2_spi,
				     .help = "show only the SA with this responder SPI"),
		    CLI_FLAG ("details", .help = "show the keys, proposals and statistics")),
  .handler = show_ikev2_sa_command_fn,
};

static clib_error_t *
ikev2_disable_dpd_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ikev2_disable_dpd ();
  return 0;
}

VLIB_CLI_COMMAND (ikev2_cli_disable_dpd_command, static) = {
  .path = "ikev2 dpd disable",
  .short_help = "Disable dead peer detection",
  .handler = ikev2_disable_dpd_command_fn,
};

static clib_error_t *
ikev2_profile_add_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_add_del_profile (vm, cli_get (ctx, "name")->str, 1);
}

static clib_error_t *
ikev2_profile_del_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_add_del_profile (vm, cli_get (ctx, "profile")->str, 0);
}

VLIB_CLI_COMMAND (ikev2_profile_add_command, static) = {
  .path = "ikev2 profile add",
  .short_help = "Add an IKEv2 profile",
  .args = CLI_ARGS (CLI_VALUE ("name", cli_type_ikev2_name)),
  .handler = ikev2_profile_add_command_fn,
};

VLIB_CLI_COMMAND (ikev2_profile_del_command, static) = {
  .path = "ikev2 profile del",
  .short_help = "Delete an IKEv2 profile",
  .args = CLI_ARGS (CLI_VALUE ("profile", cli_type_ikev2_profile)),
  .handler = ikev2_profile_del_command_fn,
};

static const cli_choice_t ikev2_encr_choices[] = {
#define _(v, f, s) { s, 0, IKEV2_TRANSFORM_ENCR_TYPE_##f },
  foreach_ikev2_transform_encr_type
#undef _
  {},
};

static const cli_choice_t ikev2_integ_choices[] = {
#define _(v, f, s) { s, 0, IKEV2_TRANSFORM_INTEG_TYPE_##f },
  foreach_ikev2_transform_integ_type
#undef _
  {},
};

static const cli_choice_t ikev2_dh_choices[] = {
#define _(v, f, s) { s, 0, IKEV2_TRANSFORM_DH_TYPE_##f },
  foreach_ikev2_transform_dh_type
#undef _
  {},
};

static const cli_choice_t ikev2_id_type_choices[] = {
#define _(v, f, s) { s, 0, IKEV2_ID_TYPE_##f },
  foreach_ikev2_id_type
#undef _
  {},
};

static const cli_choice_t ikev2_direction_choices[] = {
  { "local", 0, 1 },
  { "remote", 0, 0 },
  {},
};

static const cli_choice_t ikev2_disable_choices[] = {
  { "natt", "NAT traversal", 0 },
  {},
};

/* bytes typed as 0x<hex digits>, with an odd number of digits the first byte has one digit, 0xabc
 * is 0x0abc. An identity which does not start with 0x is text. */
static int
ikev2_hex_digit (u8 c)
{
  c = cli_to_lower (c);

  if (cli_is_digit (c))
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

static u8 *
parse_ikev2_hex0x (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u32 n = vec_len (tok), i = 2;

  if (n < 3 || tok[0] != '0' || tok[1] != 'x')
    return format (0, "'%v' is not 0x followed by hex digits", tok);

  for (u32 j = 2; j < n; j++)
    if (ikev2_hex_digit (tok[j]) < 0)
      return format (0, "'%v' is not 0x followed by hex digits", tok);

  if ((n - 2) & 1)
    vec_add1 (v->str, ikev2_hex_digit (tok[i++]));

  for (; i < n; i += 2)
    vec_add1 (v->str, ikev2_hex_digit (tok[i]) << 4 | ikev2_hex_digit (tok[i + 1]));

  return 0;
}

CLIB_CLI_TYPE (cli_type_ikev2_hex0x, static) = {
  .name = "hex",
  .help = "bytes, 0x<hex digits>",
  .usage = "0x<hex>",
  .owns_str = 1,
  .parse = parse_ikev2_hex0x,
};

static void
ikev2_cli_address (cli_value_t *v, ip_address_t *ip)
{
  ip_address_set (ip, v->prefix.addr, v->prefix.is_ip6 ? AF_IP6 : AF_IP4);
}

static clib_error_t *
ikev2_profile_set_auth (vlib_main_t *vm, cli_ctx_t *ctx, u8 *name)
{
  cli_value_t *key;
  int hex = 0;

  if (cli_flag (ctx, "rsa-sig"))
    return ikev2_set_profile_auth (vm, name, IKEV2_AUTH_METHOD_RSA_SIG,
				   cli_get (ctx, "cert-file")->str, 0);

  key = cli_get (ctx, "string");
  if (!key)
    {
      key = cli_get (ctx, "hex");
      hex = 1;
    }
  return ikev2_set_profile_auth (vm, name, IKEV2_AUTH_METHOD_SHARED_KEY_MIC, key->str, hex);
}

static clib_error_t *
ikev2_profile_set_id (vlib_main_t *vm, cli_ctx_t *ctx, u8 *name)
{
  cli_value_t *v;
  u8 *data = 0;
  clib_error_t *r;

  if ((v = cli_get (ctx, "id-address")))
    {
      ip_address_t ip;

      ikev2_cli_address (v, &ip);
      data = vec_new (u8, ip_address_size (&ip));
      clib_memcpy (data, ip_addr_bytes (&ip), ip_address_size (&ip));
    }
  else if ((v = cli_get (ctx, "id-hex")) || (v = cli_get (ctx, "id-text")))
    data = vec_dup (v->str);

  r = ikev2_set_profile_id (vm, name, cli_index (ctx, "id-type"), data,
			    cli_index (ctx, "id-direction"));
  vec_free (data);
  return r;
}

static clib_error_t *
ikev2_profile_set_ts (vlib_main_t *vm, cli_ctx_t *ctx, u8 *name)
{
  cli_value_t *first = cli_get (ctx, "ip-range"), *last = cli_get (ctx, "ip-range-end");
  ip_address_t start, end;

  if (first->prefix.is_ip6 != last->prefix.is_ip6)
    return clib_error_return (0, "ip-range needs two addresses of the same family");

  ikev2_cli_address (first, &start);
  ikev2_cli_address (last, &end);

  return ikev2_set_profile_ts (vm, name, cli_u64 (ctx, "protocol", 0),
			       cli_u64 (ctx, "port-range", 0), cli_u64 (ctx, "port-range-end", 0),
			       start, end, cli_index (ctx, "ts-direction"));
}

static clib_error_t *
ikev2_profile_set_responder (vlib_main_t *vm, cli_ctx_t *ctx, u8 *name)
{
  u32 sw_if_index = cli_index (ctx, "responder-interface");
  cli_value_t *v = cli_get (ctx, "responder-address");
  ip_address_t ip;

  if (!v)
    return ikev2_set_profile_responder_hostname (vm, name, cli_get (ctx, "responder-hostname")->str,
						 sw_if_index);

  ikev2_cli_address (v, &ip);
  return ikev2_set_profile_responder (vm, name, sw_if_index, ip);
}

static clib_error_t *
ikev2_profile_set_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u8 *name = cli_get (ctx, "profile")->str;
  int rv;

  if (cli_flag (ctx, "auth"))
    return ikev2_profile_set_auth (vm, ctx, name);
  if (cli_flag (ctx, "id"))
    return ikev2_profile_set_id (vm, ctx, name);
  if (cli_flag (ctx, "traffic-selector"))
    return ikev2_profile_set_ts (vm, ctx, name);
  if (cli_flag (ctx, "responder"))
    return ikev2_profile_set_responder (vm, ctx, name);
  if (cli_get (ctx, "tunnel"))
    return ikev2_set_profile_tunnel_interface (vm, name, cli_index (ctx, "tunnel"));
  if (cli_flag (ctx, "ike-crypto-alg"))
    return ikev2_set_profile_ike_transforms (
      vm, name, cli_index (ctx, "ike-alg"),
      cli_get (ctx, "ike-integ-alg") ? cli_index (ctx, "ike-integ-alg") :
				       IKEV2_TRANSFORM_INTEG_TYPE_NONE,
      IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256, cli_index (ctx, "ike-dh"),
      cli_u64 (ctx, "ike-key-size", 0));
  if (cli_flag (ctx, "esp-crypto-alg"))
    return ikev2_set_profile_esp_transforms (
      vm, name, cli_index (ctx, "esp-alg"),
      cli_get (ctx, "esp-integ-alg") ? cli_index (ctx, "esp-integ-alg") : 0,
      cli_u64 (ctx, "esp-key-size", 0));
  if (cli_flag (ctx, "sa-lifetime"))
    return ikev2_set_profile_sa_lifetime (vm, name, cli_u64 (ctx, "seconds", 0),
					  cli_u64 (ctx, "jitter", 0), cli_u64 (ctx, "handover", 0),
					  cli_u64 (ctx, "max-bytes", 0));
  if (cli_get (ctx, "anti-replay-window"))
    return ikev2_set_profile_anti_replay_window (name, cli_u64 (ctx, "anti-replay-window", 0));
  if (cli_flag (ctx, "udp-encap"))
    return ikev2_set_profile_udp_encap (vm, name);
  if (cli_flag (ctx, "ipsec-over-udp"))
    {
      rv = ikev2_set_profile_ipsec_udp_port (vm, name, cli_u64 (ctx, "port", 0), 1);
      if (rv)
	return clib_error_return (0, "Error: %U", format_vnet_api_errno, rv);
      return 0;
    }

  return ikev2_profile_natt_disable (name);
}

VLIB_CLI_COMMAND (ikev2_profile_set_command, static) = {
  .path = "ikev2 profile set",
  .short_help = "Set a parameter of an IKEv2 profile",
  .args = CLI_ARGS (
    CLI_VALUE ("profile", cli_type_ikev2_profile),
    CLI_ONEOF (
      "setting", 0,
      CLI_SEQ_LEAD (CLI_FLAG ("auth", .help = "authentication method and credentials"),
		    CLI_ONEOF ("auth-method", 0,
			       CLI_SEQ_LEAD (CLI_FLAG ("rsa-sig", .help = "RSA signature"),
					     CLI_KEYWORD ("cert-file", cli_type_file,
							  .help = "certificate file")),
			       CLI_SEQ_LEAD (CLI_FLAG ("shared-key-mic", .help = "pre-shared key"),
					     CLI_ONEOF ("key", 0,
							CLI_KEYWORD ("string", cli_type_string),
							CLI_KEYWORD ("hex", cli_type_hex))))),
      CLI_SEQ_LEAD (CLI_FLAG ("id", .help = "local or remote identity"),
		    CLI_VALUE ("id-direction", cli_type_enum, .choices = ikev2_direction_choices),
		    CLI_VALUE ("id-type", cli_type_enum, .choices = ikev2_id_type_choices),
		    CLI_ONEOF ("id-data", 0, CLI_VALUE ("id-address", cli_type_ip_address),
			       CLI_VALUE ("id-hex", cli_type_ikev2_hex0x),
			       CLI_VALUE ("id-text", cli_type_string))),
      CLI_SEQ_LEAD (
	CLI_FLAG ("traffic-selector", .help = "local or remote traffic selector"),
	CLI_VALUE ("ts-direction", cli_type_enum, .choices = ikev2_direction_choices),
	CLI_KEYWORD ("ip-range", cli_type_ip_address, .help = "first address"),
	CLI_VALUE ("ip-range-dash", cli_type_dash), CLI_VALUE ("ip-range-end", cli_type_ip_address),
	CLI_KEYWORD ("port-range", cli_type_u32, .max = CLIB_U16_MAX, .help = "first port"),
	CLI_VALUE ("port-range-dash", cli_type_dash),
	CLI_VALUE ("port-range-end", cli_type_u32, .max = CLIB_U16_MAX),
	CLI_KEYWORD ("protocol", cli_type_u32, .max = 255, .help = "IP protocol number, 0 is any")),
      CLI_SEQ_LEAD (CLI_FLAG ("responder", .help = "responder interface and address"),
		    CLI_VALUE ("responder-interface", cli_type_sw_interface),
		    CLI_ONEOF ("responder-to", 0,
			       CLI_VALUE ("responder-address", cli_type_ip_address),
			       CLI_VALUE ("responder-hostname", cli_type_string))),
      CLI_KEYWORD ("tunnel", cli_type_sw_interface, .help = "interface protected by the profile"),
      CLI_SEQ_LEAD (CLI_FLAG ("ike-crypto-alg", .help = "IKE SA transforms"),
		    CLI_VALUE ("ike-alg", cli_type_enum, .choices = ikev2_encr_choices),
		    CLI_VALUE ("ike-key-size", cli_type_u32, .help = "key size in bits"),
		    CLI_OPT_KEYWORD ("ike-integ-alg", cli_type_enum,
				     .choices = ikev2_integ_choices),
		    CLI_KEYWORD ("ike-dh", cli_type_enum, .choices = ikev2_dh_choices,
				 .help = "Diffie-Hellman group")),
      CLI_SEQ_LEAD (CLI_FLAG ("esp-crypto-alg", .help = "ESP transforms"),
		    CLI_VALUE ("esp-alg", cli_type_enum, .choices = ikev2_encr_choices),
		    CLI_VALUE ("esp-key-size", cli_type_u32, .help = "key size in bits"),
		    CLI_OPT_KEYWORD ("esp-integ-alg", cli_type_enum,
				     .choices = ikev2_integ_choices)),
      CLI_SEQ_LEAD (CLI_FLAG ("sa-lifetime", .help = "SA lifetime"),
		    CLI_VALUE ("seconds", cli_type_u64), CLI_VALUE ("jitter", cli_type_u32),
		    CLI_VALUE ("handover", cli_type_u32), CLI_VALUE ("max-bytes", cli_type_u64)),
      CLI_KEYWORD ("anti-replay-window", cli_type_u32, .help = "64..4096, power of two"),
      CLI_FLAG ("udp-encap", .help = "UDP encapsulation of the ESP"),
      CLI_SEQ_LEAD (CLI_FLAG ("ipsec-over-udp", .help = "UDP port of the ESP"),
		    CLI_KEYWORD ("port", cli_type_u32, .max = CLIB_U16_MAX)),
      CLI_SEQ_LEAD (CLI_FLAG ("disable", .help = "disable a feature"),
		    CLI_VALUE ("disable-what", cli_type_enum, .choices = ikev2_disable_choices)))),
  .handler = ikev2_profile_set_command_fn,
};

static clib_error_t *
show_ikev2_profile_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;

  pool_foreach (p, km->profiles)  {
    vlib_cli_output(vm, "profile %v", p->name);

    if (p->auth.data)
      {
        if (p->auth.hex)
          vlib_cli_output(vm, "  auth-method %U auth data 0x%U",
                          format_ikev2_auth_method, p->auth.method,
                          format_hex_bytes, p->auth.data, vec_len(p->auth.data));
        else
          vlib_cli_output(vm, "  auth-method %U auth data %v",
                   format_ikev2_auth_method, p->auth.method, p->auth.data);
      }

    if (p->loc_id.data)
      vlib_cli_output(vm, "  local %U", format_ikev2_id_type_and_data, &p->loc_id);

    if (p->rem_id.data)
      vlib_cli_output(vm, "  remote %U", format_ikev2_id_type_and_data, &p->rem_id);

    if (!ip_address_is_zero (&p->loc_ts.start_addr))
      vlib_cli_output(vm, "  local traffic-selector addr %U - %U port %u - %u"
                      " protocol %u",
                      format_ip_address, &p->loc_ts.start_addr,
                      format_ip_address, &p->loc_ts.end_addr,
                      p->loc_ts.start_port, p->loc_ts.end_port,
                      p->loc_ts.protocol_id);

    if (!ip_address_is_zero (&p->rem_ts.start_addr))
      vlib_cli_output(vm, "  remote traffic-selector addr %U - %U port %u - %u"
                      " protocol %u",
                      format_ip_address, &p->rem_ts.start_addr,
                      format_ip_address, &p->rem_ts.end_addr,
                      p->rem_ts.start_port, p->rem_ts.end_port,
                      p->rem_ts.protocol_id);
    if (~0 != p->tun_itf)
      vlib_cli_output(vm, "  protected tunnel %U",
                      format_vnet_sw_if_index_name, vnet_get_main(), p->tun_itf);
    if (~0 != p->responder.sw_if_index)
      vlib_cli_output (vm, "  responder %U %U %v",
		       format_vnet_sw_if_index_name, vnet_get_main (),
		       p->responder.sw_if_index, format_ip_address,
		       &p->responder.addr, p->responder.hostname);
    if (p->udp_encap)
      vlib_cli_output(vm, "  udp-encap");

    if (p->natt_disabled)
      vlib_cli_output(vm, "  NAT-T disabled");

    if (p->ipsec_over_udp_port != IPSEC_UDP_PORT_NONE)
      vlib_cli_output(vm, "  ipsec-over-udp port %d", p->ipsec_over_udp_port);

    if (p->ike_ts.crypto_alg || p->ike_ts.integ_alg || p->ike_ts.dh_type || p->ike_ts.crypto_key_size)
      vlib_cli_output(vm, "  ike-crypto-alg %U %u ike-integ-alg %U ike-dh %U",
                    format_ikev2_transform_encr_type, p->ike_ts.crypto_alg, p->ike_ts.crypto_key_size,
                    format_ikev2_transform_integ_type, p->ike_ts.integ_alg,
                    format_ikev2_transform_dh_type, p->ike_ts.dh_type);

    if (p->esp_ts.crypto_alg || p->esp_ts.integ_alg || p->esp_ts.dh_type)
      vlib_cli_output(vm, "  esp-crypto-alg %U %u esp-integ-alg %U",
                    format_ikev2_transform_encr_type, p->esp_ts.crypto_alg, p->esp_ts.crypto_key_size,
                    format_ikev2_transform_integ_type, p->esp_ts.integ_alg);

    vlib_cli_output(vm, "  lifetime %d jitter %d handover %d maxdata %d",
                    p->lifetime, p->lifetime_jitter, p->handover, p->lifetime_maxdata);
  }

  return 0;
}

VLIB_CLI_COMMAND (show_ikev2_profile_command, static) = {
  .path = "show ikev2 profile",
  .short_help = "Show the IKEv2 profiles",
  .handler = show_ikev2_profile_command_fn,
};

static clib_error_t *
set_ikev2_liveness_period_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_set_liveness_params (cli_u64 (ctx, "period", 0), cli_u64 (ctx, "max-retries", 0));
}

VLIB_CLI_COMMAND (set_ikev2_liveness_command, static) = {
  .path = "ikev2 set liveness",
  .short_help = "Set the liveness check parameters",
  .args = CLI_ARGS (CLI_VALUE ("period", cli_type_u32, .help = "seconds between the checks"),
		    CLI_VALUE ("max-retries", cli_type_u32)),
  .handler = set_ikev2_liveness_period_fn,
};

static clib_error_t *
set_ikev2_sleep_interval_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_set_sleep_interval (cli_get (ctx, "interval")->f64);
}

VLIB_CLI_COMMAND (set_ikev2_sleep_interval, static) = {
  .path = "ikev2 set sleep interval",
  .short_help = "Set the sleep interval of the IKEv2 manager",
  .args = CLI_ARGS (CLI_VALUE ("interval", cli_type_f64, .help = "seconds")),
  .handler = set_ikev2_sleep_interval_fn,
};

static clib_error_t *
show_ikev2_sleep_interval_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  f64 sleep_interval = ikev2_get_sleep_interval ();

  vlib_cli_output (vm, "IKEv2 Manager sleep interval: %.2f seconds", sleep_interval);

  return 0;
}

VLIB_CLI_COMMAND (show_ikev2_sleep_interval_command, static) = {
  .path = "show ikev2 sleep interval",
  .short_help = "Show the sleep interval of the IKEv2 manager",
  .handler = show_ikev2_sleep_interval_command_fn,
};

static clib_error_t *
set_ikev2_local_key_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_set_local_key (vm, cli_get (ctx, "file")->str);
}

VLIB_CLI_COMMAND (set_ikev2_local_key_command, static) = {
  .path = "set ikev2 local key",
  .short_help = "Set the local private key",
  .args = CLI_ARGS (CLI_VALUE ("file", cli_type_file, .help = "key file")),
  .handler = set_ikev2_local_key_command_fn,
};

static clib_error_t *
ikev2_initiate_sa_init_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_initiate_sa_init (vm, cli_get (ctx, "profile")->str);
}

static clib_error_t *
ikev2_initiate_del_child_sa_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_initiate_delete_child_sa (vm, cli_get (ctx, "ispi")->u64);
}

static clib_error_t *
ikev2_initiate_del_sa_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_initiate_delete_ike_sa (vm, cli_get (ctx, "ispi")->u64);
}

static clib_error_t *
ikev2_initiate_rekey_child_sa_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return ikev2_initiate_rekey_child_sa (vm, cli_get (ctx, "ispi")->u64);
}

VLIB_CLI_COMMAND (ikev2_initiate_sa_init_command, static) = {
  .path = "ikev2 initiate sa-init",
  .short_help = "Initiate an IKE SA for a profile",
  .args = CLI_ARGS (CLI_VALUE ("profile", cli_type_ikev2_profile)),
  .handler = ikev2_initiate_sa_init_command_fn,
};

VLIB_CLI_COMMAND (ikev2_initiate_del_child_sa_command, static) = {
  .path = "ikev2 initiate del-child-sa",
  .short_help = "Delete a child SA",
  .args = CLI_ARGS (CLI_VALUE ("ispi", cli_type_ikev2_spi, .max = CLIB_U32_MAX,
			       .help = "child SA initiator SPI")),
  .handler = ikev2_initiate_del_child_sa_command_fn,
};

VLIB_CLI_COMMAND (ikev2_initiate_del_sa_command, static) = {
  .path = "ikev2 initiate del-sa",
  .short_help = "Delete an IKE SA",
  .args = CLI_ARGS (CLI_VALUE ("ispi", cli_type_ikev2_spi, .help = "IKE SA initiator SPI")),
  .handler = ikev2_initiate_del_sa_command_fn,
};

VLIB_CLI_COMMAND (ikev2_initiate_rekey_child_sa_command, static) = {
  .path = "ikev2 initiate rekey-child-sa",
  .short_help = "Rekey a child SA",
  .args = CLI_ARGS (CLI_VALUE ("ispi", cli_type_ikev2_spi, .max = CLIB_U32_MAX,
			       .help = "child SA initiator SPI")),
  .handler = ikev2_initiate_rekey_child_sa_command_fn,
};
