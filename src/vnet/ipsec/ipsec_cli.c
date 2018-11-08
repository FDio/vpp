/*
 * decap.c : IPSec tunnel support
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#include <vnet/ipsec/ipsec.h>

static clib_error_t *
set_interface_spd_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ipsec_main_t *im = &ipsec_main;
  u32 sw_if_index = (u32) ~ 0;
  u32 spd_id;
  int is_add = 1;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat
      (line_input, "%U %u", unformat_vnet_sw_interface, im->vnet_main,
       &sw_if_index, &spd_id))
    ;
  else if (unformat (line_input, "del"))
    is_add = 0;
  else
    {
      error = clib_error_return (0, "parse error: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  ipsec_set_interface_spd (vm, sw_if_index, spd_id, is_add);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_spd_command, static) = {
    .path = "set interface ipsec spd",
    .short_help =
    "set interface ipsec spd <int> <id>",
    .function = set_interface_spd_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_sa_add_del_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ipsec_main_t *im = &ipsec_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ipsec_sa_t sa;
  int is_add = ~0;
  u8 *ck = 0, *ik = 0;
  clib_error_t *error = NULL;

  clib_memset (&sa, 0, sizeof (sa));

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %u", &sa.id))
	is_add = 1;
      else if (unformat (line_input, "del %u", &sa.id))
	is_add = 0;
      else if (unformat (line_input, "spi %u", &sa.spi))
	;
      else if (unformat (line_input, "esp"))
	sa.protocol = IPSEC_PROTOCOL_ESP;
      else if (unformat (line_input, "ah"))
	{
	  sa.protocol = IPSEC_PROTOCOL_AH;
	}
      else
	if (unformat (line_input, "crypto-key %U", unformat_hex_string, &ck))
	sa.crypto_key_len = vec_len (ck);
      else
	if (unformat
	    (line_input, "crypto-alg %U", unformat_ipsec_crypto_alg,
	     &sa.crypto_alg))
	{
	  if (sa.crypto_alg < IPSEC_CRYPTO_ALG_NONE ||
	      sa.crypto_alg >= IPSEC_CRYPTO_N_ALG)
	    {
	      error = clib_error_return (0, "unsupported crypto-alg: '%U'",
					 format_ipsec_crypto_alg,
					 sa.crypto_alg);
	      goto done;
	    }
	}
      else
	if (unformat (line_input, "integ-key %U", unformat_hex_string, &ik))
	sa.integ_key_len = vec_len (ik);
      else if (unformat (line_input, "integ-alg %U", unformat_ipsec_integ_alg,
			 &sa.integ_alg))
	{
	  if (sa.integ_alg < IPSEC_INTEG_ALG_NONE ||
	      sa.integ_alg >= IPSEC_INTEG_N_ALG)
	    {
	      error = clib_error_return (0, "unsupported integ-alg: '%U'",
					 format_ipsec_integ_alg,
					 sa.integ_alg);
	      goto done;
	    }
	}
      else if (unformat (line_input, "tunnel-src %U",
			 unformat_ip4_address, &sa.tunnel_src_addr.ip4))
	sa.is_tunnel = 1;
      else if (unformat (line_input, "tunnel-dst %U",
			 unformat_ip4_address, &sa.tunnel_dst_addr.ip4))
	sa.is_tunnel = 1;
      else if (unformat (line_input, "tunnel-src %U",
			 unformat_ip6_address, &sa.tunnel_src_addr.ip6))
	{
	  sa.is_tunnel = 1;
	  sa.is_tunnel_ip6 = 1;
	}
      else if (unformat (line_input, "tunnel-dst %U",
			 unformat_ip6_address, &sa.tunnel_dst_addr.ip6))
	{
	  sa.is_tunnel = 1;
	  sa.is_tunnel_ip6 = 1;
	}
      else if (unformat (line_input, "udp-encap"))
	{
	  sa.udp_encap = 1;
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sa.crypto_key_len > sizeof (sa.crypto_key))
    sa.crypto_key_len = sizeof (sa.crypto_key);

  if (sa.integ_key_len > sizeof (sa.integ_key))
    sa.integ_key_len = sizeof (sa.integ_key);

  if (ck)
    strncpy ((char *) sa.crypto_key, (char *) ck, sa.crypto_key_len);

  if (ik)
    strncpy ((char *) sa.integ_key, (char *) ik, sa.integ_key_len);

  if (is_add)
    {
      ASSERT (im->ah_check_support_cb);
      error = im->ah_check_support_cb (&sa);
      if (error)
	goto done;
      ASSERT (im->esp_check_support_cb);
      error = im->esp_check_support_cb (&sa);
      if (error)
	goto done;
    }

  ipsec_add_del_sa (vm, &sa, is_add);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_sa_add_del_command, static) = {
    .path = "ipsec sa",
    .short_help =
    "ipsec sa [add|del]",
    .function = ipsec_sa_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_spd_add_del_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 spd_id = ~0;
  int is_add = ~0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "%u", &spd_id))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (spd_id == ~0)
    {
      error = clib_error_return (0, "please specify SPD ID");
      goto done;
    }

  ipsec_add_del_spd (vm, spd_id, is_add);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_spd_add_del_command, static) = {
    .path = "ipsec spd",
    .short_help =
    "ipsec spd [add|del] <id>",
    .function = ipsec_spd_add_del_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
ipsec_policy_add_del_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ipsec_policy_t p;
  int is_add = 0;
  int is_ip_any = 1;
  u32 tmp, tmp2;
  clib_error_t *error = NULL;

  clib_memset (&p, 0, sizeof (p));
  p.lport.stop = p.rport.stop = ~0;
  p.laddr.stop.ip4.as_u32 = p.raddr.stop.ip4.as_u32 = (u32) ~ 0;
  p.laddr.stop.ip6.as_u64[0] = p.laddr.stop.ip6.as_u64[1] = (u64) ~ 0;
  p.raddr.stop.ip6.as_u64[0] = p.raddr.stop.ip6.as_u64[1] = (u64) ~ 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "spd %u", &p.id))
	;
      else if (unformat (line_input, "inbound"))
	p.is_outbound = 0;
      else if (unformat (line_input, "outbound"))
	p.is_outbound = 1;
      else if (unformat (line_input, "priority %d", &p.priority))
	;
      else if (unformat (line_input, "protocol %u", &tmp))
	p.protocol = (u8) tmp;
      else
	if (unformat
	    (line_input, "action %U", unformat_ipsec_policy_action,
	     &p.policy))
	{
	  if (p.policy == IPSEC_POLICY_ACTION_RESOLVE)
	    {
	      error = clib_error_return (0, "unsupported action: 'resolve'");
	      goto done;
	    }
	}
      else if (unformat (line_input, "sa %u", &p.sa_id))
	;
      else if (unformat (line_input, "local-ip-range %U - %U",
			 unformat_ip4_address, &p.laddr.start.ip4,
			 unformat_ip4_address, &p.laddr.stop.ip4))
	is_ip_any = 0;
      else if (unformat (line_input, "remote-ip-range %U - %U",
			 unformat_ip4_address, &p.raddr.start.ip4,
			 unformat_ip4_address, &p.raddr.stop.ip4))
	is_ip_any = 0;
      else if (unformat (line_input, "local-ip-range %U - %U",
			 unformat_ip6_address, &p.laddr.start.ip6,
			 unformat_ip6_address, &p.laddr.stop.ip6))
	{
	  p.is_ipv6 = 1;
	  is_ip_any = 0;
	}
      else if (unformat (line_input, "remote-ip-range %U - %U",
			 unformat_ip6_address, &p.raddr.start.ip6,
			 unformat_ip6_address, &p.raddr.stop.ip6))
	{
	  p.is_ipv6 = 1;
	  is_ip_any = 0;
	}
      else if (unformat (line_input, "local-port-range %u - %u", &tmp, &tmp2))
	{
	  p.lport.start = tmp;
	  p.lport.stop = tmp2;
	}
      else
	if (unformat (line_input, "remote-port-range %u - %u", &tmp, &tmp2))
	{
	  p.rport.start = tmp;
	  p.rport.stop = tmp2;
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* Check if SA is for IPv6/AH which is not supported. Return error if TRUE. */
  if (p.sa_id)
    {
      uword *p1;
      ipsec_main_t *im = &ipsec_main;
      ipsec_sa_t *sa = 0;
      p1 = hash_get (im->sa_index_by_sa_id, p.sa_id);
      if (!p1)
	{
	  error =
	    clib_error_return (0, "SA with index %u not found", p.sa_id);
	  goto done;
	}
      sa = pool_elt_at_index (im->sad, p1[0]);
      if (sa && sa->protocol == IPSEC_PROTOCOL_AH && is_add && p.is_ipv6)
	{
	  error = clib_error_return (0, "AH not supported for IPV6: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
  ipsec_add_del_policy (vm, &p, is_add);
  if (is_ip_any)
    {
      p.is_ipv6 = 1;
      ipsec_add_del_policy (vm, &p, is_add);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_policy_add_del_command, static) = {
    .path = "ipsec policy",
    .short_help =
    "ipsec policy [add|del] spd <id> priority <n> ",
    .function = ipsec_policy_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_ipsec_sa_key_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ipsec_sa_t sa;
  u8 *ck = 0, *ik = 0;
  clib_error_t *error = NULL;

  clib_memset (&sa, 0, sizeof (sa));

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &sa.id))
	;
      else
	if (unformat (line_input, "crypto-key %U", unformat_hex_string, &ck))
	sa.crypto_key_len = vec_len (ck);
      else
	if (unformat (line_input, "integ-key %U", unformat_hex_string, &ik))
	sa.integ_key_len = vec_len (ik);
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sa.crypto_key_len > sizeof (sa.crypto_key))
    sa.crypto_key_len = sizeof (sa.crypto_key);

  if (sa.integ_key_len > sizeof (sa.integ_key))
    sa.integ_key_len = sizeof (sa.integ_key);

  if (ck)
    strncpy ((char *) sa.crypto_key, (char *) ck, sa.crypto_key_len);

  if (ik)
    strncpy ((char *) sa.integ_key, (char *) ik, sa.integ_key_len);

  ipsec_set_sa_key (vm, &sa);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ipsec_sa_key_command, static) = {
    .path = "set ipsec sa",
    .short_help =
    "set ipsec sa <id> crypto-key <key> integ-key <key>",
    .function = set_ipsec_sa_key_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_ipsec_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ipsec_spd_t *spd;
  ipsec_sa_t *sa;
  ipsec_policy_t *p;
  ipsec_main_t *im = &ipsec_main;
  u32 *i;
  ipsec_tunnel_if_t *t;
  vnet_hw_interface_t *hi;
  u8 *protocol = NULL;
  u8 *policy = NULL;

  /* *INDENT-OFF* */
  pool_foreach (sa, im->sad, ({
    if (sa->id) {
      vlib_cli_output(vm, "sa %u spi %u mode %s protocol %s%s", sa->id, sa->spi,
                      sa->is_tunnel ? "tunnel" : "transport",
                      sa->protocol ? "esp" : "ah",
		      sa->udp_encap ? " udp-encap-enabled" : "");
      if (sa->protocol == IPSEC_PROTOCOL_ESP) {
        vlib_cli_output(vm, "  crypto alg %U%s%U integrity alg %U%s%U",
                        format_ipsec_crypto_alg, sa->crypto_alg,
                        sa->crypto_alg ? " key " : "",
                        format_hex_bytes, sa->crypto_key, sa->crypto_key_len,
                        format_ipsec_integ_alg, sa->integ_alg,
                        sa->integ_alg ? " key " : "",
                        format_hex_bytes, sa->integ_key, sa->integ_key_len);
      }
      if (sa->is_tunnel && sa->is_tunnel_ip6) {
        vlib_cli_output(vm, "  tunnel src %U dst %U",
                        format_ip6_address, &sa->tunnel_src_addr.ip6,
                        format_ip6_address, &sa->tunnel_dst_addr.ip6);
      } else if (sa->is_tunnel) {
        vlib_cli_output(vm, "  tunnel src %U dst %U",
                        format_ip4_address, &sa->tunnel_src_addr.ip4,
                        format_ip4_address, &sa->tunnel_dst_addr.ip4);
      }
    }
  }));
  /* *INDENT-ON* */

  /* *INDENT-OFF* */
  pool_foreach (spd, im->spds, ({
    vlib_cli_output(vm, "spd %u", spd->id);

    vlib_cli_output(vm, " outbound policies");
    vec_foreach(i, spd->ipv4_outbound_policies)
      {
        p = pool_elt_at_index(spd->policies, *i);
	vec_reset_length(protocol);
	vec_reset_length(policy);
	if (p->protocol) {
	  protocol = format(protocol, "%U", format_ip_protocol, p->protocol);
	} else {
	  protocol = format(protocol, "any");
	}
	if (p->policy == IPSEC_POLICY_ACTION_PROTECT) {
	  policy = format(policy, " sa %u", p->sa_id);
	}

        vlib_cli_output(vm, "  priority %d action %U protocol %v%v",
                        p->priority, format_ipsec_policy_action, p->policy,
			protocol, policy);
        vlib_cli_output(vm, "   local addr range %U - %U port range %u - %u",
                        format_ip4_address, &p->laddr.start.ip4,
                        format_ip4_address, &p->laddr.stop.ip4,
                        p->lport.start, p->lport.stop);
        vlib_cli_output(vm, "   remote addr range %U - %U port range %u - %u",
                        format_ip4_address, &p->raddr.start.ip4,
                        format_ip4_address, &p->raddr.stop.ip4,
                        p->rport.start, p->rport.stop);
        vlib_cli_output(vm, "   packets %u bytes %u", p->counter.packets,
                        p->counter.bytes);
      };
    vec_foreach(i, spd->ipv6_outbound_policies)
      {
        p = pool_elt_at_index(spd->policies, *i);
	vec_reset_length(protocol);
	vec_reset_length(policy);
	if (p->protocol) {
	  protocol = format(protocol, "%U", format_ip_protocol, p->protocol);
	} else {
	  protocol = format(protocol, "any");
	}
	if (p->policy == IPSEC_POLICY_ACTION_PROTECT) {
	  policy = format(policy, " sa %u", p->sa_id);
	}
        vlib_cli_output(vm, "  priority %d action %U protocol %v%v",
                        p->priority, format_ipsec_policy_action, p->policy,
			protocol, policy);
        vlib_cli_output(vm, "   local addr range %U - %U port range %u - %u",
                        format_ip6_address, &p->laddr.start.ip6,
                        format_ip6_address, &p->laddr.stop.ip6,
                        p->lport.start, p->lport.stop);
        vlib_cli_output(vm, "   remote addr range %U - %U port range %u - %u",
                        format_ip6_address, &p->raddr.start.ip6,
                        format_ip6_address, &p->raddr.stop.ip6,
                        p->rport.start, p->rport.stop);
        vlib_cli_output(vm, "   packets %u bytes %u", p->counter.packets,
                        p->counter.bytes);
      };
    vlib_cli_output(vm, " inbound policies");
    vec_foreach(i, spd->ipv4_inbound_protect_policy_indices)
      {
        p = pool_elt_at_index(spd->policies, *i);
	vec_reset_length(protocol);
	vec_reset_length(policy);
	if (p->protocol) {
	  protocol = format(protocol, "%U", format_ip_protocol, p->protocol);
	} else {
	  protocol = format(protocol, "any");
	}
	if (p->policy == IPSEC_POLICY_ACTION_PROTECT) {
	  policy = format(policy, " sa %u", p->sa_id);
	}
        vlib_cli_output(vm, "  priority %d action %U protocol %v%v",
                        p->priority, format_ipsec_policy_action, p->policy,
			protocol, policy);
        vlib_cli_output(vm, "   local addr range %U - %U port range %u - %u",
                        format_ip4_address, &p->laddr.start.ip4,
                        format_ip4_address, &p->laddr.stop.ip4,
                        p->lport.start, p->lport.stop);
        vlib_cli_output(vm, "   remote addr range %U - %U port range %u - %u",
                        format_ip4_address, &p->raddr.start.ip4,
                        format_ip4_address, &p->raddr.stop.ip4,
                        p->rport.start, p->rport.stop);
        vlib_cli_output(vm, "   packets %u bytes %u", p->counter.packets,
                        p->counter.bytes);
      };
    vec_foreach(i, spd->ipv4_inbound_policy_discard_and_bypass_indices)
      {
        p = pool_elt_at_index(spd->policies, *i);
	vec_reset_length(protocol);
	vec_reset_length(policy);
	if (p->protocol) {
	  protocol = format(protocol, "%U", format_ip_protocol, p->protocol);
	} else {
	  protocol = format(protocol, "any");
	}
	if (p->policy == IPSEC_POLICY_ACTION_PROTECT) {
	  policy = format(policy, " sa %u", p->sa_id);
	}
        vlib_cli_output(vm, "  priority %d action %U protocol %v%v",
                        p->priority, format_ipsec_policy_action, p->policy,
			protocol, policy);
        vlib_cli_output(vm, "   local addr range %U - %U port range %u - %u",
                        format_ip4_address, &p->laddr.start.ip4,
                        format_ip4_address, &p->laddr.stop.ip4,
                        p->lport.start, p->lport.stop);
        vlib_cli_output(vm, "   remote addr range %U - %U port range %u - %u",
                        format_ip4_address, &p->raddr.start.ip4,
                        format_ip4_address, &p->raddr.stop.ip4,
                        p->rport.start, p->rport.stop);
        vlib_cli_output(vm, "   packets %u bytes %u", p->counter.packets,
                        p->counter.bytes);
      };
    vec_foreach(i, spd->ipv6_inbound_protect_policy_indices)
      {
        p = pool_elt_at_index(spd->policies, *i);
	vec_reset_length(protocol);
	vec_reset_length(policy);
	if (p->protocol) {
	  protocol = format(protocol, "%U", format_ip_protocol, p->protocol);
	} else {
	  protocol = format(protocol, "any");
	}
	if (p->policy == IPSEC_POLICY_ACTION_PROTECT) {
	  policy = format(policy, " sa %u", p->sa_id);
	}
        vlib_cli_output(vm, "  priority %d action %U protocol %v%v",
                        p->priority, format_ipsec_policy_action, p->policy,
			protocol, policy);
        vlib_cli_output(vm, "   local addr range %U - %U port range %u - %u",
                        format_ip6_address, &p->laddr.start.ip6,
                        format_ip6_address, &p->laddr.stop.ip6,
                        p->lport.start, p->lport.stop);
        vlib_cli_output(vm, "   remote addr range %U - %U port range %u - %u",
                        format_ip6_address, &p->raddr.start.ip6,
                        format_ip6_address, &p->raddr.stop.ip6,
                        p->rport.start, p->rport.stop);
        vlib_cli_output(vm, "   packets %u bytes %u", p->counter.packets,
                        p->counter.bytes);
      };
    vec_foreach(i, spd->ipv6_inbound_policy_discard_and_bypass_indices)
      {
        p = pool_elt_at_index(spd->policies, *i);
	vec_reset_length(protocol);
	vec_reset_length(policy);
	if (p->protocol) {
	  protocol = format(protocol, "%U", format_ip_protocol, p->protocol);
	} else {
	  protocol = format(protocol, "any");
	}
	if (p->policy == IPSEC_POLICY_ACTION_PROTECT) {
	  policy = format(policy, " sa %u", p->sa_id);
	}
        vlib_cli_output(vm, "  priority %d action %U protocol %v%v",
                        p->priority, format_ipsec_policy_action, p->policy,
			protocol, policy);
        vlib_cli_output(vm, "   local addr range %U - %U port range %u - %u",
                        format_ip6_address, &p->laddr.start.ip6,
                        format_ip6_address, &p->laddr.stop.ip6,
                        p->lport.start, p->lport.stop);
        vlib_cli_output(vm, "   remote addr range %U - %U port range %u - %u",
                        format_ip6_address, &p->raddr.start.ip6,
                        format_ip6_address, &p->raddr.stop.ip6,
                        p->rport.start, p->rport.stop);
        vlib_cli_output(vm, "   packets %u bytes %u", p->counter.packets,
                        p->counter.bytes);
      };
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "tunnel interfaces");
  /* *INDENT-OFF* */
  pool_foreach (t, im->tunnel_interfaces, ({
    if (t->hw_if_index == ~0)
      continue;
    hi = vnet_get_hw_interface (im->vnet_main, t->hw_if_index);
    vlib_cli_output(vm, "  %s seq", hi->name);
    sa = pool_elt_at_index(im->sad, t->output_sa_index);
    vlib_cli_output(vm, "   seq %u seq-hi %u esn %u anti-replay %u udp-encap %u",
                    sa->seq, sa->seq_hi, sa->use_esn, sa->use_anti_replay, sa->udp_encap);
    vlib_cli_output(vm, "   local-spi %u local-ip %U", sa->spi,
                    format_ip4_address, &sa->tunnel_src_addr.ip4);
    vlib_cli_output(vm, "   local-crypto %U %U",
                    format_ipsec_crypto_alg, sa->crypto_alg,
                    format_hex_bytes, sa->crypto_key, sa->crypto_key_len);
    vlib_cli_output(vm, "   local-integrity %U %U",
                    format_ipsec_integ_alg, sa->integ_alg,
                    format_hex_bytes, sa->integ_key, sa->integ_key_len);
    sa = pool_elt_at_index(im->sad, t->input_sa_index);
    vlib_cli_output(vm, "   last-seq %u last-seq-hi %u esn %u anti-replay %u window %U",
                    sa->last_seq, sa->last_seq_hi, sa->use_esn,
                    sa->use_anti_replay,
                    format_ipsec_replay_window, sa->replay_window);
    vlib_cli_output(vm, "   remote-spi %u remote-ip %U", sa->spi,
                    format_ip4_address, &sa->tunnel_src_addr.ip4);
    vlib_cli_output(vm, "   remote-crypto %U %U",
                    format_ipsec_crypto_alg, sa->crypto_alg,
                    format_hex_bytes, sa->crypto_key, sa->crypto_key_len);
    vlib_cli_output(vm, "   remote-integrity %U %U",
                    format_ipsec_integ_alg, sa->integ_alg,
                    format_hex_bytes, sa->integ_key, sa->integ_key_len);
  }));
  vec_free(policy);
  vec_free(protocol);
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ipsec_command, static) = {
    .path = "show ipsec",
    .short_help = "show ipsec [backends]",
    .function = show_ipsec_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_show_backends_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  ipsec_main_t *im = &ipsec_main;

  vlib_cli_output (vm, "IPsec AH backends available:");
  u8 *s = format (NULL, "%=25s %=25s %=10s\n", "Name", "Index", "Active");
  ipsec_ah_backend_t *ab;
  /* *INDENT-OFF* */
  pool_foreach (ab, im->ah_backends, {
    s = format (s, "%=25s %=25u %=10s\n", ab->name, ab - im->ah_backends,
                ab - im->ah_backends == im->ah_current_backend ? "yes" : "no");
  });
  /* *INDENT-ON* */
  vlib_cli_output (vm, "%v", s);
  _vec_len (s) = 0;
  vlib_cli_output (vm, "IPsec ESP backends available:");
  s = format (s, "%=25s %=25s %=10s\n", "Name", "Index", "Active");
  ipsec_esp_backend_t *eb;
  /* *INDENT-OFF* */
  pool_foreach (eb, im->esp_backends, {
    s = format (s, "%=25s %=25u %=10s\n", eb->name, eb - im->esp_backends,
                eb - im->esp_backends == im->esp_current_backend ? "yes"
                                                                 : "no");
  });
  /* *INDENT-ON* */
  vlib_cli_output (vm, "%v", s);

  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_show_backends_command, static) = {
    .path = "ipsec show backends",
    .short_help = "ipsec show backends",
    .function = ipsec_show_backends_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_select_backend_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  u32 backend_index;
  ipsec_main_t *im = &ipsec_main;

  if (pool_elts (im->sad) > 0)
    {
      return clib_error_return (0,
				"Cannot change IPsec backend, while %u SA entries are configured",
				pool_elts (im->sad));
    }

  unformat_input_t _line_input, *line_input = &_line_input;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "ah"))
    {
      if (unformat (line_input, "%u", &backend_index))
	{
	  if (ipsec_select_ah_backend (im, backend_index) < 0)
	    {
	      return clib_error_return (0, "Invalid AH backend index `%u'",
					backend_index);
	    }
	}
      else
	{
	  return clib_error_return (0, "Invalid backend index `%U'",
				    format_unformat_error, line_input);
	}
    }
  else if (unformat (line_input, "esp"))
    {
      if (unformat (line_input, "%u", &backend_index))
	{
	  if (ipsec_select_esp_backend (im, backend_index) < 0)
	    {
	      return clib_error_return (0, "Invalid ESP backend index `%u'",
					backend_index);
	    }
	}
      else
	{
	  return clib_error_return (0, "Invalid backend index `%U'",
				    format_unformat_error, line_input);
	}
    }
  else
    {
      return clib_error_return (0, "Unknown input `%U'",
				format_unformat_error, line_input);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_select_backend_command, static) = {
    .path = "ipsec select backend",
    .short_help = "ipsec select backend <ah|esp> <backend index>",
    .function = ipsec_select_backend_command_fn,
};

/* *INDENT-ON* */

static clib_error_t *
clear_ipsec_counters_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd;
  ipsec_policy_t *p;

  /* *INDENT-OFF* */
  pool_foreach (spd, im->spds, ({
    pool_foreach(p, spd->policies, ({
      p->counter.packets = p->counter.bytes = 0;
    }));
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_ipsec_counters_command, static) = {
    .path = "clear ipsec counters",
    .short_help = "clear ipsec counters",
    .function = clear_ipsec_counters_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
create_ipsec_tunnel_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ipsec_add_del_tunnel_args_t a;
  int rv;
  u32 num_m_args = 0;
  clib_error_t *error = NULL;

  clib_memset (&a, 0, sizeof (a));
  a.is_add = 1;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "local-ip %U", unformat_ip4_address, &a.local_ip))
	num_m_args++;
      else
	if (unformat
	    (line_input, "remote-ip %U", unformat_ip4_address, &a.remote_ip))
	num_m_args++;
      else if (unformat (line_input, "local-spi %u", &a.local_spi))
	num_m_args++;
      else if (unformat (line_input, "remote-spi %u", &a.remote_spi))
	num_m_args++;
      else if (unformat (line_input, "instance %u", &a.show_instance))
	a.renumber = 1;
      else if (unformat (line_input, "del"))
	a.is_add = 0;
      else if (unformat (line_input, "udp-encap"))
	a.udp_encap = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (num_m_args < 4)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  rv = ipsec_add_del_tunnel_if (&a);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      if (a.is_add)
	error = clib_error_return (0,
				   "IPSec tunnel interface already exists...");
      else
	error = clib_error_return (0, "IPSec tunnel interface not exists...");
      goto done;
    default:
      error = clib_error_return (0, "ipsec_register_interface returned %d",
				 rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_ipsec_tunnel_command, static) = {
  .path = "create ipsec tunnel",
  .short_help = "create ipsec tunnel local-ip <addr> local-spi <spi> remote-ip <addr> remote-spi <spi> [instance <inst_num>] [udp-encap]",
  .function = create_ipsec_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_interface_key_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ipsec_main_t *im = &ipsec_main;
  ipsec_if_set_key_type_t type = IPSEC_IF_SET_KEY_TYPE_NONE;
  u32 hw_if_index = (u32) ~ 0;
  u32 alg;
  u8 *key = 0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_hw_interface, im->vnet_main, &hw_if_index))
	;
      else
	if (unformat
	    (line_input, "local crypto %U", unformat_ipsec_crypto_alg, &alg))
	type = IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO;
      else
	if (unformat
	    (line_input, "remote crypto %U", unformat_ipsec_crypto_alg, &alg))
	type = IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO;
      else
	if (unformat
	    (line_input, "local integ %U", unformat_ipsec_integ_alg, &alg))
	type = IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG;
      else
	if (unformat
	    (line_input, "remote integ %U", unformat_ipsec_integ_alg, &alg))
	type = IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG;
      else if (unformat (line_input, "%U", unformat_hex_string, &key))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (type == IPSEC_IF_SET_KEY_TYPE_NONE)
    {
      error = clib_error_return (0, "unknown key type");
      goto done;
    }

  if (alg > 0 && vec_len (key) == 0)
    {
      error = clib_error_return (0, "key is not specified");
      goto done;
    }

  if (hw_if_index == (u32) ~ 0)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  ipsec_set_interface_key (im->vnet_main, hw_if_index, type, alg, key);

done:
  vec_free (key);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_key_command, static) = {
    .path = "set interface ipsec key",
    .short_help =
    "set interface ipsec key <int> <local|remote> <crypto|integ> <key type> <key>",
    .function = set_interface_key_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
ipsec_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_cli_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
