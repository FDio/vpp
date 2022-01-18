/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief DET44 CLI
 */
#include <nat/det44/det44.h>

#define DET44_EXPECTED_ARGUMENT "expected required argument(s)"

static clib_error_t *
det44_map_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u32 in_plen, out_plen;
  u32 ses_per_user = ~0;
  u32 tcp_per_user = ~0, udp_per_user = ~0, other_per_user = ~0;
  int is_add = 1, rv;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "in %U/%u", unformat_ip4_address, &in_addr, &in_plen))
	;
      else
	if (unformat
	    (line_input, "out %U/%u", unformat_ip4_address, &out_addr,
	     &out_plen))
	;
      else if (unformat (line_input, "ses %u", &ses_per_user))
	;
      else if (unformat (line_input, "tcp %u", &tcp_per_user))
	;
      else if (unformat (line_input, "udp %u", &udp_per_user))
	;
      else if (unformat (line_input, "other %u", &other_per_user))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = snat_det_add_map (&in_addr, (u8) in_plen, &out_addr, (u8) out_plen,
			 ses_per_user, tcp_per_user, udp_per_user,
			 other_per_user, is_add);
  if (rv)
    {
      error = clib_error_return (0, "snat_det_add_map return %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
det44_show_mappings_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  det44_main_t *dm = &det44_main;
  snat_det_map_t *mp;
  vlib_cli_output (vm, "NAT44 deterministic mappings:");
  pool_foreach (mp, dm->det_maps)
   {
    vlib_cli_output (vm, " in %U/%d out %U/%d\n",
                     format_ip4_address, &mp->in_addr, mp->in_plen,
                     format_ip4_address, &mp->out_addr, mp->out_plen);
    vlib_cli_output (vm, "  outside address sharing ratio: %d\n",
                     mp->sharing_ratio);
    vlib_cli_output (vm, "  number of ports per inside host: %d\n",
                     mp->ports_per_host);
    vlib_cli_output (vm, "  number of sessions per inside host: %d\n",
		     mp->ses_per_user);
    vlib_cli_output (vm, "  sessions number: %d\n", mp->ses_num);
  }
  return 0;
}

static clib_error_t *
det44_forward_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u16 lo_port;
  snat_det_map_t *mp;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &in_addr))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  mp = snat_det_map_by_user (&in_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_forward (mp, &in_addr, &out_addr, &lo_port);
      vlib_cli_output (vm, "%U:<%d-%d>", format_ip4_address, &out_addr,
		       lo_port, lo_port + mp->ports_per_host - 1);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
det44_reverse_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  clib_error_t *error = 0;
  snat_det_map_t *mp;
  u32 out_port;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U:%d", unformat_ip4_address, &out_addr, &out_port))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (out_port < 1024 || out_port > 65535)
    {
      error = clib_error_return (0, "wrong port, must be <1024-65535>");
      goto done;
    }

  mp = snat_det_map_by_out (&out_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (mp, &out_addr, (u16) out_port, &in_addr);
      vlib_cli_output (vm, "%U", format_ip4_address, &in_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
det44_show_sessions_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  det44_main_t *dm = &det44_main;
  snat_det_session_t *ses;
  snat_det_map_t *mp;
  vlib_cli_output (vm, "NAT44 deterministic sessions:");
  pool_foreach (mp, dm->det_maps)
   {
    int i;
    vec_foreach_index (i, mp->sessions)
      {
        ses = vec_elt_at_index (mp->sessions, i);
        if (ses->in_port)
          vlib_cli_output (vm, "  %U", format_det_map_ses, mp, ses, &i);
      }
  }
  return 0;
}

static clib_error_t *
det44_close_session_out_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t out_addr, ext_addr, in_addr;
  u32 out_port, ext_port;
  u16 proto;
  snat_det_map_t *mp;
  snat_det_session_t *ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d %U", unformat_ip4_address,
		    &out_addr, &out_port, unformat_ip4_address, &ext_addr,
		    &ext_port, unformat_ip_protocol, &proto))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  unformat_free (line_input);

  mp = snat_det_map_by_out (&out_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (mp, &ext_addr, (u16) out_port, &in_addr);
      key.ext_host_addr = out_addr;
      key.ext_host_port = ntohs ((u16) ext_port);
      key.out_port = ntohs ((u16) out_port);
      ses = snat_det_get_ses_by_out (mp, &out_addr, key.as_u64, proto);
      if (!ses)
	vlib_cli_output (vm, "no match");
      else
	snat_det_ses_close (mp, ses);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
det44_close_session_in_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, ext_addr;
  u32 in_port, ext_port;
  u16 proto;
  snat_det_map_t *mp;
  snat_det_session_t *ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d %U", unformat_ip4_address,
		    &in_addr, &in_port, unformat_ip4_address, &ext_addr,
		    &ext_port, unformat_ip_protocol, &proto))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  unformat_free (line_input);

  mp = snat_det_map_by_user (&in_addr);
  if (!mp)
    vlib_cli_output (vm, "no match");
  else
    {
      key.ext_host_addr = ext_addr;
      key.ext_host_port = ntohs ((u16) ext_port);
      ses = snat_det_find_ses_by_in (mp, &in_addr, ntohs ((u16) in_port), key,
				     proto);
      if (!ses)
	vlib_cli_output (vm, "no match");
      else
	snat_det_ses_close (mp, ses);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
det44_set_timeouts_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat_timeouts_t timeouts = { 0 };
  clib_error_t *error = 0;
  u8 reset = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &timeouts.udp));
      else if (unformat (line_input, "tcp established %u",
			 &timeouts.tcp.established));
      else if (unformat (line_input, "tcp transitory %u",
			 &timeouts.tcp.transitory));
      else if (unformat (line_input, "icmp %u", &timeouts.icmp));
      else if (unformat (line_input, "reset"))
	reset = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!reset)
    {
      if (det44_set_timeouts (&timeouts))
	{
	  error = clib_error_return (0, "error configuring timeouts");
	}
    }
  else
    det44_reset_timeouts ();
done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
det44_show_timeouts_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  nat_timeouts_t timeouts;
  timeouts = det44_get_timeouts ();
  vlib_cli_output (vm, "udp timeout: %dsec", timeouts.udp);
  vlib_cli_output (vm, "tcp established timeout: %dsec",
		   timeouts.tcp.established);
  vlib_cli_output (vm, "tcp transitory timeout: %dsec",
		   timeouts.tcp.transitory);
  vlib_cli_output (vm, "icmp timeout: %dsec", timeouts.icmp);
  return 0;
}

static clib_error_t *
det44_plugin_enable_disable_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 enable = 0, is_set = 0;
  clib_error_t *error = 0;
  det44_config_t c = { 0 };

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!is_set && unformat (line_input, "enable"))
	{
	  unformat (line_input, "inside vrf %u", &c.inside_vrf_id);
	  unformat (line_input, "outside vrf %u", &c.outside_vrf_id);
	  enable = 1;
	}
      else if (!is_set && unformat (line_input, "disable"));
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
      is_set = 1;
    }

  if (enable)
    {
      if (det44_plugin_enable (c))
	error = clib_error_return (0, "plugin enable failed");
    }
  else
    {
      if (det44_plugin_disable ())
	error = clib_error_return (0, "plugin disable failed");
    }
done:
  unformat_free (line_input);
  return error;
}

typedef struct
{
  u32 sw_if_index;
  u8 is_inside;
} sw_if_indices_t;

static clib_error_t *
det44_feature_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  sw_if_indices_t *sw_if_indices = 0, *p, e;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u8 is_del = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, DET44_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "inside %U", unformat_vnet_sw_interface,
		    vnm, &e.sw_if_index))
	{
	  e.is_inside = 1;
	  vec_add1 (sw_if_indices, e);
	}
      else if (unformat (line_input, "outside %U", unformat_vnet_sw_interface,
			 vnm, &e.sw_if_index))
	{
	  e.is_inside = 0;
	  vec_add1 (sw_if_indices, e);
	}
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vec_foreach (p, sw_if_indices)
    {
      if (det44_interface_add_del (p->sw_if_index, p->is_inside, is_del))
        {
          error = clib_error_return (0, "%s %s %U failed",
                                     is_del ? "del" : "add",
                                     p->is_inside ? "inside" : "outside",
				     format_vnet_sw_if_index_name,
				     vnm, p->sw_if_index);
          break;
        }
    }
done:
  unformat_free (line_input);
  vec_free (sw_if_indices);
  return error;
}

static clib_error_t *
det44_show_interfaces_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  det44_main_t *dm = &det44_main;
  det44_interface_t *i;
  vlib_cli_output (vm, "DET44 interfaces:");
  pool_foreach (i, dm->interfaces)
   {
    vlib_cli_output (vm, " %U %s", format_vnet_sw_if_index_name, vnm,
                     i->sw_if_index,
                     (det44_interface_is_inside(i) &&
                      det44_interface_is_outside(i)) ? "in out" :
                     (det44_interface_is_inside(i) ? "in" : "out"));
  }
  return 0;
}

/*?
 * @cliexpar
 * @cliexstart{det44 add}
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling DET44 to reduce logging in CGN
 * deployments.
 * To create mapping between inside network 10.0.0.0/18 and
 * outside network 1.1.1.0/30 use:
 * # vpp# det44 add in 10.0.0.0/18 out 1.1.1.0/30
 * To specify number of sessions per inside host
 * # vpp# det44 add in 10.0.0.0/18 out 1.1.1.0/30 ses 60
 * TO limit number of host sessions per protocol other
 * # vpp# det44 add in 10.0.0.0/18 out 1.1.1.0/30 other 100
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_map_command, static) = {
  .path = "det44 add",
  .short_help = "det44 add in <addr>/<plen> out <addr>/<plen> "
		"[ses <num>] [tcp <num>] [udp <num>] [other <num>] "
		"[del]",
  .function = det44_map_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show det44 mappings}
 * Show DET44 mappings
 * vpp# show det44 mappings
 * DET44 mappings:
 *  in 10.0.0.0/24 out 1.1.1.1/32
 *   outside address sharing ratio: 256
 *   number of ports per inside host: 252
 *   number of sessions per inside host: 1000
 *   sessions number: 0
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_show_mappings_command, static) = {
    .path = "show det44 mappings",
    .short_help = "show det44 mappings",
    .function = det44_show_mappings_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{det44 forward}
 * Return outside address and port range from inside address for DET44.
 * To obtain outside address and port of inside host use:
 *  vpp# det44 forward 10.0.0.2
 *  1.1.1.0:<1054-1068>
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_forward_command, static) = {
    .path = "det44 forward",
    .short_help = "det44 forward <addr>",
    .function = det44_forward_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{det44 reverse}
 * Return inside address from outside address and port for DET44.
 * To obtain inside host address from outside address and port use:
 *  #vpp det44 reverse 1.1.1.1:1276
 *  10.0.16.16
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_reverse_command, static) = {
    .path = "det44 reverse",
    .short_help = "det44 reverse <addr>:<port>",
    .function = det44_reverse_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show det44 sessions}
 * Show DET44 sessions.
 * vpp# show det44 sessions
 * DET44 sessions:
 *   in 10.0.0.3:3005 out 1.1.1.2:1146 external host 172.16.1.2:3006 state: udp-active expire: 306
 *   in 10.0.0.3:3000 out 1.1.1.2:1141 external host 172.16.1.2:3001 state: udp-active expire: 306
 *   in 10.0.0.4:3005 out 1.1.1.2:1177 external host 172.16.1.2:3006 state: udp-active expire: 306
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_show_sessions_command, static) = {
  .path = "show det44 sessions",
  .short_help = "show det44 sessions",
  .function = det44_show_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{det44 close session out}
 * Close session using outside ip address and port
 * and external ip address and port, use:
 *  vpp# det44 close session out 1.1.1.1:1276 2.2.2.2:2387 tcp
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_close_sesion_out_command, static) = {
  .path = "det44 close session out",
  .short_help = "det44 close session out "
		"<out_addr>:<out_port> <ext_addr>:<ext_port> <proto>",
  .function = det44_close_session_out_fn,
};

/*?
 * @cliexpar
 * @cliexstart{det44 deterministic close session in}
 * Close session using inside ip address and port
 * and external ip address and port, use:
 *  vpp# det44 close session in 3.3.3.3:3487 2.2.2.2:2387 tcp
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_close_session_in_command, static) = {
  .path = "det44 close session in",
  .short_help = "det44 close session in "
		"<in_addr>:<in_port> <ext_addr>:<ext_port> <proto>",
  .function = det44_close_session_in_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set det44 timeout}
 * Set values of timeouts for DET44 sessions (in seconds), use:
 *  vpp# set det44 timeouts udp 120 tcp established 7500 tcp transitory 250 icmp 90
 * To reset default values use:
 *  vpp# set det44 timeouts reset
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_set_timeouts_command, static) =
{
  .path = "set det44 timeouts",
  .short_help = "set det44 timeouts <[udp <sec>] [tcp established <sec>] "
                "[tcp transitory <sec>] [icmp <sec>]|reset>",
  .function = det44_set_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show det44 timeouts}
 * Show values of timeouts for DET44 sessions.
 * vpp# show det44 timeouts
 * udp timeout: 300sec
 * tcp-established timeout: 7440sec
 * tcp-transitory timeout: 240sec
 * icmp timeout: 60sec
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_show_timeouts_command, static) =
{
  .path = "show det44 timeouts",
  .short_help = "show det44 timeouts",
  .function = det44_show_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{det44 plugin}
 * Enable/disable DET44 plugin.
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_plugin_enable_disable_command, static) =
{
  .path = "det44 plugin",
  .short_help = "det44 plugin <enable [inside vrf] [outside vrf]|disable>",
  .function = det44_plugin_enable_disable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface det44}
 * Enable/disable DET44 feature on the interface.
 * To enable DET44 feature with local network interface use:
 *  vpp# set interface det44 inside GigabitEthernet0/8/0
 * To enable DET44 feature with external network interface use:
 *  vpp# set interface det44 outside GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_feature_command, static) =
{
  .path = "set interface det44",
  .short_help = "set interface det44 inside <intfc> outside <intfc> [del]",
  .function = det44_feature_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show det44 interfaces}
 * Show interfaces with DET44 feature.
 * vpp# show det44 interfaces
 * DET44 interfaces:
 *  GigabitEthernet0/8/0 in
 *  GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (det44_show_interfaces_command, static) =
{
  .path = "show det44 interfaces",
  .short_help = "show det44 interfaces",
  .function = det44_show_interfaces_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
