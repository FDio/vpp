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
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/ikev2_priv.h>

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


static clib_error_t *
show_ikev2_sa_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;
  ikev2_ts_t *ts;
  ikev2_child_sa_t *child;
  ikev2_sa_transform_t *tr;

  vec_foreach (tkm, km->per_thread_data)
  {
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      u8 * s = 0;
      vlib_cli_output(vm, " iip %U ispi %lx rip %U rspi %lx",
                      format_ip4_address, &sa->iaddr, sa->ispi,
                      format_ip4_address, &sa->raddr, sa->rspi);

       tr = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
       s = format(s, "%U ", format_ikev2_sa_transform, tr);

       tr = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
       s = format(s, "%U ", format_ikev2_sa_transform, tr);

       tr = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);
       s = format(s, "%U ", format_ikev2_sa_transform, tr);

       tr = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_DH);
       s = format(s, "%U ", format_ikev2_sa_transform, tr);

      vlib_cli_output(vm, " %v", s);
      vec_free(s);

      vlib_cli_output(vm, "  nonce i:%U\n        r:%U",
                      format_hex_bytes, sa->i_nonce,  vec_len(sa->i_nonce),
                      format_hex_bytes, sa->r_nonce,  vec_len(sa->r_nonce));

      vlib_cli_output(vm, "  SK_d    %U",
                      format_hex_bytes, sa->sk_d,  vec_len(sa->sk_d));
      vlib_cli_output(vm, "  SK_a  i:%U\n        r:%U",
                      format_hex_bytes, sa->sk_ai, vec_len(sa->sk_ai),
                      format_hex_bytes, sa->sk_ar, vec_len(sa->sk_ar));
      vlib_cli_output(vm, "  SK_e  i:%U\n        r:%U",
                      format_hex_bytes, sa->sk_ei, vec_len(sa->sk_ei),
                      format_hex_bytes, sa->sk_er, vec_len(sa->sk_er));
      vlib_cli_output(vm, "  SK_p  i:%U\n        r:%U",
                      format_hex_bytes, sa->sk_pi, vec_len(sa->sk_pi),
                      format_hex_bytes, sa->sk_pr, vec_len(sa->sk_pr));

      vlib_cli_output(vm, "  identifier (i) %U",
                      format_ikev2_id_type_and_data, &sa->i_id);
      vlib_cli_output(vm, "  identifier (r) %U",
                      format_ikev2_id_type_and_data, &sa->r_id);

      vec_foreach(child, sa->childs)
        {
          vlib_cli_output(vm, "  child sa %u:", child - sa->childs);

          tr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
          s = format(s, "%U ", format_ikev2_sa_transform, tr);

          tr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);
          s = format(s, "%U ", format_ikev2_sa_transform, tr);

          tr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_ESN);
          s = format(s, "%U ", format_ikev2_sa_transform, tr);

          vlib_cli_output(vm, "    %v", s);
          vec_free(s);

          vlib_cli_output(vm, "    spi(i) %lx spi(r) %lx",
                          child->i_proposals ? child->i_proposals[0].spi : 0,
                          child->r_proposals ? child->r_proposals[0].spi : 0);

          vlib_cli_output(vm, "    SK_e  i:%U\n          r:%U",
                          format_hex_bytes, child->sk_ei, vec_len(child->sk_ei),
                          format_hex_bytes, child->sk_er, vec_len(child->sk_er));
          vlib_cli_output(vm, "    SK_a  i:%U\n          r:%U",
                          format_hex_bytes, child->sk_ai, vec_len(child->sk_ai),
                          format_hex_bytes, child->sk_ar, vec_len(child->sk_ar));
          vlib_cli_output(vm, "    traffic selectors (i):");
          vec_foreach(ts, child->tsi)
            {
              vlib_cli_output(vm, "      %u type %u protocol_id %u addr "
                              "%U - %U port %u - %u",
                              ts - child->tsi,
                              ts->ts_type, ts->protocol_id,
                              format_ip4_address, &ts->start_addr,
                              format_ip4_address, &ts->end_addr,
                              clib_net_to_host_u16( ts->start_port),
                              clib_net_to_host_u16( ts->end_port));
            }
          vlib_cli_output(vm, "    traffic selectors (r):");
          vec_foreach(ts, child->tsr)
            {
              vlib_cli_output(vm, "      %u type %u protocol_id %u addr "
                              "%U - %U port %u - %u",
                              ts - child->tsr,
                              ts->ts_type, ts->protocol_id,
                              format_ip4_address, &ts->start_addr,
                              format_ip4_address, &ts->end_addr,
                              clib_net_to_host_u16( ts->start_port),
                              clib_net_to_host_u16( ts->end_port));
            }
        }
      vlib_cli_output(vm, "");
    }));
    /* *INDENT-ON* */
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ikev2_sa_command, static) = {
    .path = "show ikev2 sa",
    .short_help = "show ikev2 sa",
    .function = show_ikev2_sa_command_fn,
};
/* *INDENT-ON* */

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
  ip4_address_t responder_ip4;
  ikev2_transform_encr_type_t crypto_alg;
  ikev2_transform_integ_type_t integ_alg;
  ikev2_transform_dh_type_t dh_type;

  const char *valid_chars = "a-zA-Z0-9_";

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add %U", unformat_token, valid_chars, &name))
	{
	  r = ikev2_add_del_profile (vm, name, 1);
	  goto done;
	}
      else
	if (unformat
	    (line_input, "del %U", unformat_token, valid_chars, &name))
	{
	  r = ikev2_add_del_profile (vm, name, 0);
	  goto done;
	}
      else if (unformat (line_input, "set %U auth shared-key-mic string %v",
			 unformat_token, valid_chars, &name, &data))
	{
	  r =
	    ikev2_set_profile_auth (vm, name,
				    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, data,
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U auth shared-key-mic hex %U",
			 unformat_token, valid_chars, &name,
			 unformat_hex_string, &data))
	{
	  r =
	    ikev2_set_profile_auth (vm, name,
				    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, data,
				    1);
	  goto done;
	}
      else if (unformat (line_input, "set %U auth rsa-sig cert-file %v",
			 unformat_token, valid_chars, &name, &data))
	{
	  r =
	    ikev2_set_profile_auth (vm, name, IKEV2_AUTH_METHOD_RSA_SIG, data,
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U id local %U %U",
			 unformat_token, valid_chars, &name,
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
			 unformat_token, valid_chars, &name,
			 unformat_ikev2_id_type, &id_type,
			 unformat_hex_string, &data))
	{
	  r =
	    ikev2_set_profile_id (vm, name, (u8) id_type, data, /*local */ 1);
	  goto done;
	}
      else if (unformat (line_input, "set %U id local %U %v",
			 unformat_token, valid_chars, &name,
			 unformat_ikev2_id_type, &id_type, &data))
	{
	  r =
	    ikev2_set_profile_id (vm, name, (u8) id_type, data, /*local */ 1);
	  goto done;
	}
      else if (unformat (line_input, "set %U id remote %U %U",
			 unformat_token, valid_chars, &name,
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
			 unformat_token, valid_chars, &name,
			 unformat_ikev2_id_type, &id_type,
			 unformat_hex_string, &data))
	{
	  r = ikev2_set_profile_id (vm, name, (u8) id_type, data,	/*remote */
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U id remote %U %v",
			 unformat_token, valid_chars, &name,
			 unformat_ikev2_id_type, &id_type, &data))
	{
	  r = ikev2_set_profile_id (vm, name, (u8) id_type, data,	/*remote */
				    0);
	  goto done;
	}
      else if (unformat (line_input, "set %U traffic-selector local "
			 "ip-range %U - %U port-range %u - %u protocol %u",
			 unformat_token, valid_chars, &name,
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
			 unformat_token, valid_chars, &name,
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
			 unformat_token, valid_chars, &name,
			 unformat_vnet_sw_interface, vnm,
			 &responder_sw_if_index, unformat_ip4_address,
			 &responder_ip4))
	{
	  r =
	    ikev2_set_profile_responder (vm, name, responder_sw_if_index,
					 responder_ip4);
	  goto done;
	}
      else
	if (unformat
	    (line_input,
	     "set %U ike-crypto-alg %U %u ike-integ-alg %U ike-dh %U",
	     unformat_token, valid_chars, &name,
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
	     "set %U esp-crypto-alg %U %u esp-integ-alg %U esp-dh %U",
	     unformat_token, valid_chars, &name,
	     unformat_ikev2_transform_encr_type, &crypto_alg, &tmp1,
	     unformat_ikev2_transform_integ_type, &integ_alg,
	     unformat_ikev2_transform_dh_type, &dh_type))
	{
	  r =
	    ikev2_set_profile_esp_transforms (vm, name, crypto_alg, integ_alg,
					      dh_type, tmp1);
	  goto done;
	}
      else if (unformat (line_input, "set %U sa-lifetime %lu %u %u %lu",
			 unformat_token, valid_chars, &name,
			 &tmp4, &tmp1, &tmp2, &tmp5))
	{
	  r =
	    ikev2_set_profile_sa_lifetime (vm, name, tmp4, tmp1, tmp2, tmp5);
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
    "ikev2 profile set <id> traffic-selector <local|remote> ip-range "
    "<start-addr> - <end-addr> port-range <start-port> - <end-port> "
    "protocol <protocol-number>\n"
    "ikev2 profile set <id> responder <interface> <addr>\n"
    "ikev2 profile set <id> ike-crypto-alg <crypto alg> <key size> ike-integ-alg <integ alg> ike-dh <dh type>\n"
    "ikev2 profile set <id> esp-crypto-alg <crypto alg> <key size> esp-integ-alg <integ alg> esp-dh <dh type>\n"
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

  const char *valid_chars = "a-zA-Z0-9_";

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "sa-init %U", unformat_token, valid_chars, &name))
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


clib_error_t *
ikev2_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ikev2_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
