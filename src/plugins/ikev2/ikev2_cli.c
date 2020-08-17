/*
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/udp/udp.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <plugins/ikev2/ikev2.h>
#include <plugins/ikev2/ikev2_priv.h>

u8 *
format_ikev2_id_type_and_data (u8 * s, va_list * args)
{
  ikev2_id_t *id = va_arg (*args, ikev2_id_t *);

  if (id->type == 0 || vec_len (id->data) == 0)
    return format (s, "none");

  s = format (s, "%U", format_ikev2_id_type, id->type);

  if (id->type == IKEV2_ID_TYPE_ID_FQDN ||
      id->type == IKEV2_ID_TYPE_ID_RFC822_ADDR)
    {
      s = format (s, " %v", id->data);
    }
  else
    {
      s =
	format (s, " %U", format_hex_bytes, &id->data,
		(uword) (vec_len (id->data)));
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
	      format_ip4_address, &ts->start_addr,
	      format_ip4_address, &ts->end_addr,
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

  u32 indent = format_get_indent (s);
  indent += 1;

  s = format (s, "child sa %u:", index);

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

static u8 *
format_ikev2_sa (u8 * s, va_list * va)
{
  ikev2_sa_t *sa = va_arg (*va, ikev2_sa_t *);
  int details = va_arg (*va, int);
  ikev2_sa_transform_t *tr;
  ikev2_child_sa_t *child;
  u32 indent = 1;

  s = format (s, "iip %U ispi %lx rip %U rspi %lx",
	      format_ip4_address, &sa->iaddr, sa->ispi,
	      format_ip4_address, &sa->raddr, sa->rspi);
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

  return s;
}

static clib_error_t *
show_ikev2_sa_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;
  u64 rspi;
  u8 *s = 0;
  int details = 0, show_one = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "rspi %lx", &rspi))
	    {
	      show_one = 1;
	    }
	  else if (unformat (line_input, "details"))
	    details = 1;
	  else
	    break;
	}
      unformat_free (line_input);
    }

  vec_foreach (tkm, km->per_thread_data)
  {
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      if (show_one)
        {
          if (sa->rspi == rspi)
            {
              s = format (s, "%U\n", format_ikev2_sa, sa, 1);
              break;
            }
        }
      else
        s = format (s, "%U\n", format_ikev2_sa, sa, details);
    }));
    /* *INDENT-ON* */
  }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ikev2_sa_command, static) = {
    .path = "show ikev2 sa",
    .short_help = "show ikev2 sa [rspi <rspi>] [details]",
    .function = show_ikev2_sa_command_fn,
};
/* *INDENT-ON* */

static uword
unformat_ikev2_token (unformat_input_t * input, va_list * va)
{
  u8 **string_return = va_arg (*va, u8 **);
  const char *token_chars = "a-zA-Z0-9_";
  if (*string_return)
    {
      /* if string_return was already allocated (eg. because of a previous
       * partial match with a successful unformat_token()), we must free it
       * before reusing the pointer, otherwise we'll be leaking memory
       */
      vec_free (*string_return);
      *string_return = 0;
    }
  return unformat_user (input, unformat_token, token_chars, string_return);
}

static clib_error_t *
ikev2_profile_add_del_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = 0;
  clib_error_t *r = 0;
  u32 id_type;
  u8 *data = 0;
  u32 tmp1, tmp2, tmp3;
  u64 tmp4, tmp5;
  ip4_address_t ip4;
  ip4_address_t end_addr;
  u32 responder_sw_if_index = (u32) ~ 0;
  u32 tun_sw_if_index = (u32) ~ 0;
  ip4_address_t responder_ip4;
  ikev2_transform_encr_type_t crypto_alg;
  ikev2_transform_integ_type_t integ_alg;
  ikev2_transform_dh_type_t dh_type;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %U", unformat_ikev2_token, &name))
	{
	  r = ikev2_add_del_profile (vm, name, 1);
	  goto done;
	}
      else if (unformat (line_input, "del %U", unformat_ikev2_token, &name))
	{
	  r = ikev2_add_del_profile (vm, name, 0);
	  goto done;
	}
      else if (unformat (line_input, "set %U auth shared-key-mic string %v",
			 unformat_ikev2_token, &name, &data))
	{
	  r =
	    ikev2_set_profile_auth (vm, name,
				    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, data,
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U auth shared-key-mic hex %U",
			 unformat_ikev2_token, &name,
			 unformat_hex_string, &data))
	{
	  r =
	    ikev2_set_profile_auth (vm, name,
				    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, data,
				    1);
	  goto done;
	}
      else if (unformat (line_input, "set %U auth rsa-sig cert-file %v",
			 unformat_ikev2_token, &name, &data))
	{
	  r =
	    ikev2_set_profile_auth (vm, name, IKEV2_AUTH_METHOD_RSA_SIG, data,
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U id local %U %U",
			 unformat_ikev2_token, &name,
			 unformat_ikev2_id_type, &id_type,
			 unformat_ip4_address, &ip4))
	{
	  data = vec_new (u8, 4);
	  clib_memcpy (data, ip4.as_u8, 4);
	  r =
	    ikev2_set_profile_id (vm, name, (u8) id_type, data, /*local */ 1);
	  goto done;
	}
      else if (unformat (line_input, "set %U id local %U 0x%U",
			 unformat_ikev2_token, &name,
			 unformat_ikev2_id_type, &id_type,
			 unformat_hex_string, &data))
	{
	  r =
	    ikev2_set_profile_id (vm, name, (u8) id_type, data, /*local */ 1);
	  goto done;
	}
      else if (unformat (line_input, "set %U id local %U %v",
			 unformat_ikev2_token, &name,
			 unformat_ikev2_id_type, &id_type, &data))
	{
	  r =
	    ikev2_set_profile_id (vm, name, (u8) id_type, data, /*local */ 1);
	  goto done;
	}
      else if (unformat (line_input, "set %U id remote %U %U",
			 unformat_ikev2_token, &name,
			 unformat_ikev2_id_type, &id_type,
			 unformat_ip4_address, &ip4))
	{
	  data = vec_new (u8, 4);
	  clib_memcpy (data, ip4.as_u8, 4);
	  r = ikev2_set_profile_id (vm, name, (u8) id_type, data,	/*remote */
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U id remote %U 0x%U",
			 unformat_ikev2_token, &name,
			 unformat_ikev2_id_type, &id_type,
			 unformat_hex_string, &data))
	{
	  r = ikev2_set_profile_id (vm, name, (u8) id_type, data,	/*remote */
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U id remote %U %v",
			 unformat_ikev2_token, &name,
			 unformat_ikev2_id_type, &id_type, &data))
	{
	  r = ikev2_set_profile_id (vm, name, (u8) id_type, data,	/*remote */
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U traffic-selector local "
			 "ip-range %U - %U port-range %u - %u protocol %u",
			 unformat_ikev2_token, &name,
			 unformat_ip4_address, &ip4,
			 unformat_ip4_address, &end_addr,
			 &tmp1, &tmp2, &tmp3))
	{
	  r =
	    ikev2_set_profile_ts (vm, name, (u8) tmp3, (u16) tmp1, (u16) tmp2,
				  ip4, end_addr, /*local */ 1);
	  goto done;
	}
      else if (unformat (line_input, "set %U traffic-selector remote "
			 "ip-range %U - %U port-range %u - %u protocol %u",
			 unformat_ikev2_token, &name,
			 unformat_ip4_address, &ip4,
			 unformat_ip4_address, &end_addr,
			 &tmp1, &tmp2, &tmp3))
	{
	  r =
	    ikev2_set_profile_ts (vm, name, (u8) tmp3, (u16) tmp1, (u16) tmp2,
				  ip4, end_addr, /*remote */ 0);
	  goto done;
	}
      else if (unformat (line_input, "set %U responder %U %U",
			 unformat_ikev2_token, &name,
			 unformat_vnet_sw_interface, vnm,
			 &responder_sw_if_index, unformat_ip4_address,
			 &responder_ip4))
	{
	  r =
	    ikev2_set_profile_responder (vm, name, responder_sw_if_index,
					 responder_ip4);
	  goto done;
	}
      else if (unformat (line_input, "set %U tunnel %U",
			 unformat_ikev2_token, &name,
			 unformat_vnet_sw_interface, vnm, &tun_sw_if_index))
	{
	  r = ikev2_set_profile_tunnel_interface (vm, name, tun_sw_if_index);
	  goto done;
	}
      else
	if (unformat
	    (line_input,
	     "set %U ike-crypto-alg %U %u ike-integ-alg %U ike-dh %U",
	     unformat_ikev2_token, &name,
	     unformat_ikev2_transform_encr_type, &crypto_alg, &tmp1,
	     unformat_ikev2_transform_integ_type, &integ_alg,
	     unformat_ikev2_transform_dh_type, &dh_type))
	{
	  r =
	    ikev2_set_profile_ike_transforms (vm, name, crypto_alg, integ_alg,
					      dh_type, tmp1);
	  goto done;
	}
      else
	if (unformat
	    (line_input,
	     "set %U ike-crypto-alg %U %u ike-dh %U",
	     unformat_ikev2_token, &name,
	     unformat_ikev2_transform_encr_type, &crypto_alg, &tmp1,
	     unformat_ikev2_transform_dh_type, &dh_type))
	{
	  r =
	    ikev2_set_profile_ike_transforms (vm, name, crypto_alg,
					      IKEV2_TRANSFORM_INTEG_TYPE_NONE,
					      dh_type, tmp1);
	  goto done;
	}
      else
	if (unformat
	    (line_input,
	     "set %U esp-crypto-alg %U %u esp-integ-alg %U",
	     unformat_ikev2_token, &name,
	     unformat_ikev2_transform_encr_type, &crypto_alg, &tmp1,
	     unformat_ikev2_transform_integ_type, &integ_alg))
	{
	  r =
	    ikev2_set_profile_esp_transforms (vm, name, crypto_alg, integ_alg,
					      tmp1);
	  goto done;
	}
      else if (unformat
	       (line_input,
		"set %U esp-crypto-alg %U %u",
		unformat_ikev2_token, &name,
		unformat_ikev2_transform_encr_type, &crypto_alg, &tmp1))
	{
	  r =
	    ikev2_set_profile_esp_transforms (vm, name, crypto_alg, 0, tmp1);
	  goto done;
	}
      else if (unformat (line_input, "set %U sa-lifetime %lu %u %u %lu",
			 unformat_ikev2_token, &name,
			 &tmp4, &tmp1, &tmp2, &tmp5))
	{
	  r =
	    ikev2_set_profile_sa_lifetime (vm, name, tmp4, tmp1, tmp2, tmp5);
	  goto done;
	}
      else if (unformat (line_input, "set %U udp-encap",
			 unformat_ikev2_token, &name))
	{
	  r = ikev2_set_profile_udp_encap (vm, name);
	  goto done;
	}
      else if (unformat (line_input, "set %U ipsec-over-udp port %u",
			 unformat_ikev2_token, &name, &tmp1))
	{
	  int rv = ikev2_set_profile_ipsec_udp_port (vm, name, tmp1, 1);
	  if (rv)
	    r = clib_error_return (0, "Error: %U", format_vnet_api_errno, rv);
	  goto done;
	}
      else
	break;
    }

  r = clib_error_return (0, "parse error: '%U'",
			 format_unformat_error, line_input);

done:
  vec_free (name);
  vec_free (data);
  unformat_free (line_input);
  return r;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ikev2_profile_add_del_command, static) = {
    .path = "ikev2 profile",
    .short_help =
    "ikev2 profile [add|del] <id>\n"
    "ikev2 profile set <id> auth [rsa-sig|shared-key-mic] [cert-file|string|hex]"
    " <data>\n"
    "ikev2 profile set <id> id <local|remote> <type> <data>\n"
    "ikev2 profile set <id> tunnel <interface>\n"
    "ikev2 profile set <id> udp-encap\n"
    "ikev2 profile set <id> traffic-selector <local|remote> ip-range "
    "<start-addr> - <end-addr> port-range <start-port> - <end-port> "
    "protocol <protocol-number>\n"
    "ikev2 profile set <id> responder <interface> <addr>\n"
    "ikev2 profile set <id> ike-crypto-alg <crypto alg> <key size> ike-integ-alg <integ alg> ike-dh <dh type>\n"
    "ikev2 profile set <id> esp-crypto-alg <crypto alg> <key size> "
      "[esp-integ-alg <integ alg>]\n"
    "ikev2 profile set <id> sa-lifetime <seconds> <jitter> <handover> <max bytes>",
    .function = ikev2_profile_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_ikev2_profile_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({
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
      {
        if (p->loc_id.type == IKEV2_ID_TYPE_ID_IPV4_ADDR)
          vlib_cli_output(vm, "  local id-type %U data %U",
                          format_ikev2_id_type, p->loc_id.type,
                          format_ip4_address, p->loc_id.data);
        else if (p->loc_id.type == IKEV2_ID_TYPE_ID_KEY_ID)
          vlib_cli_output(vm, "  local id-type %U data 0x%U",
                          format_ikev2_id_type, p->loc_id.type,
                          format_hex_bytes, p->loc_id.data,
                          vec_len(p->loc_id.data));
        else
          vlib_cli_output(vm, "  local id-type %U data %v",
                          format_ikev2_id_type, p->loc_id.type, p->loc_id.data);
      }

    if (p->rem_id.data)
      {
        if (p->rem_id.type == IKEV2_ID_TYPE_ID_IPV4_ADDR)
          vlib_cli_output(vm, "  remote id-type %U data %U",
                          format_ikev2_id_type, p->rem_id.type,
                          format_ip4_address, p->rem_id.data);
        else if (p->rem_id.type == IKEV2_ID_TYPE_ID_KEY_ID)
          vlib_cli_output(vm, "  remote id-type %U data 0x%U",
                          format_ikev2_id_type, p->rem_id.type,
                          format_hex_bytes, p->rem_id.data,
                          vec_len(p->rem_id.data));
        else
          vlib_cli_output(vm, "  remote id-type %U data %v",
                          format_ikev2_id_type, p->rem_id.type, p->rem_id.data);
      }

    if (p->loc_ts.end_addr.as_u32)
      vlib_cli_output(vm, "  local traffic-selector addr %U - %U port %u - %u"
                      " protocol %u",
                      format_ip4_address, &p->loc_ts.start_addr,
                      format_ip4_address, &p->loc_ts.end_addr,
                      p->loc_ts.start_port, p->loc_ts.end_port,
                      p->loc_ts.protocol_id);

    if (p->rem_ts.end_addr.as_u32)
      vlib_cli_output(vm, "  remote traffic-selector addr %U - %U port %u - %u"
                      " protocol %u",
                      format_ip4_address, &p->rem_ts.start_addr,
                      format_ip4_address, &p->rem_ts.end_addr,
                      p->rem_ts.start_port, p->rem_ts.end_port,
                      p->rem_ts.protocol_id);
    if (~0 != p->tun_itf)
      vlib_cli_output(vm, "  protected tunnel %U",
                      format_vnet_sw_if_index_name, vnet_get_main(), p->tun_itf);
    if (~0 != p->responder.sw_if_index)
      vlib_cli_output(vm, "  responder %U %U",
                      format_vnet_sw_if_index_name, vnet_get_main(), p->responder.sw_if_index,
                      format_ip4_address, &p->responder.ip4);
    if (p->udp_encap)
      vlib_cli_output(vm, "  udp-encap");

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
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ikev2_profile_command, static) = {
    .path = "show ikev2 profile",
    .short_help = "show ikev2 profile",
    .function = show_ikev2_profile_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_ikev2_liveness_period_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *r = 0;
  u32 period = 0, max_retries = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d %d", &period, &max_retries))
	{
	  r = ikev2_set_liveness_params (period, max_retries);
	  goto done;
	}
      else
	break;
    }

  r = clib_error_return (0, "parse error: '%U'",
			 format_unformat_error, line_input);

done:
  unformat_free (line_input);
  return r;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ikev2_liveness_command, static) = {
  .path = "ikev2 set liveness",
  .short_help = "ikev2 set liveness <period> <max-retires>",
  .function = set_ikev2_liveness_period_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_ikev2_local_key_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *r = 0;
  u8 *data = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &data))
	{
	  r = ikev2_set_local_key (vm, data);
	  goto done;
	}
      else
	break;
    }

  r = clib_error_return (0, "parse error: '%U'",
			 format_unformat_error, line_input);

done:
  vec_free (data);
  unformat_free (line_input);
  return r;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ikev2_local_key_command, static) = {
    .path = "set ikev2 local key",
    .short_help =
    "set ikev2 local key <file>",
    .function = set_ikev2_local_key_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
ikev2_initiate_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *r = 0;
  u8 *name = 0;
  u32 tmp1;
  u64 tmp2;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sa-init %U", unformat_ikev2_token, &name))
	{
	  r = ikev2_initiate_sa_init (vm, name);
	  goto done;
	}
      else if (unformat (line_input, "del-child-sa %x", &tmp1))
	{
	  r = ikev2_initiate_delete_child_sa (vm, tmp1);
	  goto done;
	}
      else if (unformat (line_input, "del-sa %lx", &tmp2))
	{
	  r = ikev2_initiate_delete_ike_sa (vm, tmp2);
	  goto done;
	}
      else if (unformat (line_input, "rekey-child-sa %x", &tmp1))
	{
	  r = ikev2_initiate_rekey_child_sa (vm, tmp1);
	  goto done;
	}
      else
	break;
    }

  r = clib_error_return (0, "parse error: '%U'",
			 format_unformat_error, line_input);

done:
  vec_free (name);
  unformat_free (line_input);
  return r;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ikev2_initiate_command, static) = {
    .path = "ikev2 initiate",
    .short_help =
        "ikev2 initiate sa-init <profile id>\n"
        "ikev2 initiate del-child-sa <child sa ispi>\n"
        "ikev2 initiate del-sa <sa ispi>\n"
        "ikev2 initiate rekey-child-sa <profile id> <child sa ispi>\n",
    .function = ikev2_initiate_command_fn,
};
/* *INDENT-ON* */

void
ikev2_cli_reference (void)
{
}

static clib_error_t *
ikev2_set_log_level_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 log_level = IKEV2_LOG_NONE;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat (line_input, "%d", &log_level))
    {
      error = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  int rc = ikev2_set_log_level (log_level);
  if (rc < 0)
    error = clib_error_return (0, "setting log level failed!");

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ikev2_set_log_level_command, static) = {
  .path = "ikev2 set logging level",
  .function = ikev2_set_log_level_command_fn,
  .short_help = "ikev2 set logging level <0-5>",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
