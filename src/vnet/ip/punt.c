/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * @brief Local TCP/IP stack punt infrastructure.
 *
 * Provides a set of VPP nodes together with the relevant APIs and CLI
 * commands in order to adjust and dispatch packets from the VPP data plane
 * to the local TCP/IP stack
 */

#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/ip/punt.h>
#include <vlib/unix/unix.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>

punt_main_t punt_main;

char *
vnet_punt_get_server_pathname (void)
{
  punt_main_t *pm = &punt_main;
  return pm->sun_path;
}

static void
punt_client_l4_db_add (ip_address_family_t af, u16 port, u32 index)
{
  punt_main_t *pm = &punt_main;

  pm->db.clients_by_l4_port = hash_set (pm->db.clients_by_l4_port,
					punt_client_l4_mk_key (af, port),
					index);
}

static u32
punt_client_l4_db_remove (ip_address_family_t af, u16 port)
{
  punt_main_t *pm = &punt_main;
  u32 key, index = ~0;
  uword *p;

  key = punt_client_l4_mk_key (af, port);
  p = hash_get (pm->db.clients_by_l4_port, key);

  if (p)
    index = p[0];

  hash_unset (pm->db.clients_by_l4_port, key);

  return (index);
}

static void
punt_client_ip_proto_db_add (ip_address_family_t af,
			     ip_protocol_t proto, u32 index)
{
  punt_main_t *pm = &punt_main;

  pm->db.clients_by_ip_proto = hash_set (pm->db.clients_by_ip_proto,
					 punt_client_ip_proto_mk_key (af,
								      proto),
					 index);
}

static u32
punt_client_ip_proto_db_remove (ip_address_family_t af, ip_protocol_t proto)
{
  punt_main_t *pm = &punt_main;
  u32 key, index = ~0;
  uword *p;

  key = punt_client_ip_proto_mk_key (af, proto);
  p = hash_get (pm->db.clients_by_ip_proto, key);

  if (p)
    index = p[0];

  hash_unset (pm->db.clients_by_ip_proto, key);

  return (index);
}

static void
punt_client_exception_db_add (vlib_punt_reason_t reason, u32 pci)
{
  punt_main_t *pm = &punt_main;

  vec_validate_init_empty (pm->db.clients_by_exception, reason, ~0);

  pm->db.clients_by_exception[reason] = pci;
}

static u32
punt_client_exception_db_remove (vlib_punt_reason_t reason)
{
  punt_main_t *pm = &punt_main;
  u32 pci = ~0;

  if (punt_client_exception_get (reason))
    {
      pci = pm->db.clients_by_exception[reason];
      pm->db.clients_by_exception[reason] = ~0;
    }

  return pci;
}

static clib_error_t *
punt_socket_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  punt_main_t *pm = &punt_main;

  /** Schedule the rx node */
  vlib_node_set_interrupt_pending (vm, punt_socket_rx_node.index);
  vec_add1 (pm->ready_fds, uf->file_descriptor);

  return 0;
}

static clib_error_t *
punt_socket_register_l4 (vlib_main_t * vm,
			 ip_address_family_t af,
			 u8 protocol, u16 port, char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t *c;

  /* For now we only support UDP punt */
  if (protocol != IP_PROTOCOL_UDP)
    return clib_error_return (0,
			      "only UDP protocol (%d) is supported, got %d",
			      IP_PROTOCOL_UDP, protocol);

  if (port == (u16) ~ 0)
    return clib_error_return (0, "UDP port number required");

  c = punt_client_l4_get (af, port);

  if (NULL == c)
    {
      pool_get_zero (pm->punt_client_pool, c);
      punt_client_l4_db_add (af, port, c - pm->punt_client_pool);
    }

  memcpy (c->caddr.sun_path, client_pathname, sizeof (c->caddr.sun_path));
  c->caddr.sun_family = AF_UNIX;
  c->reg.type = PUNT_TYPE_L4;
  c->reg.punt.l4.port = port;
  c->reg.punt.l4.protocol = protocol;
  c->reg.punt.l4.af = af;

  u32 node_index = (af == AF_IP4 ?
		    udp4_punt_socket_node.index :
		    udp6_punt_socket_node.index);

  udp_register_dst_port (vm, port, node_index, af == AF_IP4);

  return (NULL);
}

static clib_error_t *
punt_socket_register_ip_proto (vlib_main_t * vm,
			       ip_address_family_t af,
			       ip_protocol_t proto, char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t *c;

  c = punt_client_ip_proto_get (af, proto);

  if (NULL == c)
    {
      pool_get_zero (pm->punt_client_pool, c);
      punt_client_ip_proto_db_add (af, proto, c - pm->punt_client_pool);
    }

  memcpy (c->caddr.sun_path, client_pathname, sizeof (c->caddr.sun_path));
  c->caddr.sun_family = AF_UNIX;
  c->reg.type = PUNT_TYPE_IP_PROTO;
  c->reg.punt.ip_proto.protocol = proto;
  c->reg.punt.ip_proto.af = af;

  if (af == AF_IP4)
    ip4_register_protocol (proto, ip4_proto_punt_socket_node.index);
  else
    ip6_register_protocol (proto, ip6_proto_punt_socket_node.index);

  return (NULL);
}

static clib_error_t *
punt_socket_register_exception (vlib_main_t * vm,
				vlib_punt_reason_t reason,
				char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t *pc;

  pc = punt_client_exception_get (reason);

  if (NULL == pc)
    {
      pool_get_zero (pm->punt_client_pool, pc);
      punt_client_exception_db_add (reason, pc - pm->punt_client_pool);
    }

  memcpy (pc->caddr.sun_path, client_pathname, sizeof (pc->caddr.sun_path));
  pc->caddr.sun_family = AF_UNIX;
  pc->reg.type = PUNT_TYPE_EXCEPTION;
  pc->reg.punt.exception.reason = reason;

  vlib_punt_register (pm->hdl,
		      pc->reg.punt.exception.reason, "exception-punt-socket");

  return (NULL);
}

static clib_error_t *
punt_socket_unregister_l4 (ip_address_family_t af,
			   ip_protocol_t protocol, u16 port)
{
  u32 pci;

  udp_unregister_dst_port (vlib_get_main (), port, af == AF_IP4);

  pci = punt_client_l4_db_remove (af, port);

  if (~0 != pci)
    pool_put_index (punt_main.punt_client_pool, pci);

  return (NULL);
}

static clib_error_t *
punt_socket_unregister_ip_proto (ip_address_family_t af, ip_protocol_t proto)
{
  u32 pci;

  if (af == AF_IP4)
    ip4_unregister_protocol (proto);
  else
    ip6_unregister_protocol (proto);

  pci = punt_client_ip_proto_db_remove (af, proto);

  if (~0 != pci)
    pool_put_index (punt_main.punt_client_pool, pci);

  return (NULL);
}

static clib_error_t *
punt_socket_unregister_exception (vlib_punt_reason_t reason)
{
  u32 pci;

  pci = punt_client_exception_db_remove (reason);

  if (~0 != pci)
    pool_put_index (punt_main.punt_client_pool, pci);

  return (NULL);
}

clib_error_t *
vnet_punt_socket_add (vlib_main_t * vm, u32 header_version,
		      const punt_reg_t * pr, char *client_pathname)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return (0, "socket is not configured");

  if (header_version != PUNT_PACKETDESC_VERSION)
    return clib_error_return (0, "Invalid packet descriptor version");

  if (strncmp (client_pathname, vnet_punt_get_server_pathname (),
	       UNIX_PATH_MAX) == 0)
    return clib_error_return (0,
			      "Punt socket: Invalid client path: %s",
			      client_pathname);

  /* Register client */
  switch (pr->type)
    {
    case PUNT_TYPE_L4:
      return (punt_socket_register_l4 (vm,
				       pr->punt.l4.af,
				       pr->punt.l4.protocol,
				       pr->punt.l4.port, client_pathname));
    case PUNT_TYPE_IP_PROTO:
      return (punt_socket_register_ip_proto (vm,
					     pr->punt.ip_proto.af,
					     pr->punt.ip_proto.protocol,
					     client_pathname));
    case PUNT_TYPE_EXCEPTION:
      return (punt_socket_register_exception (vm,
					      pr->punt.exception.reason,
					      client_pathname));
    }

  return 0;
}

clib_error_t *
vnet_punt_socket_del (vlib_main_t * vm, const punt_reg_t * pr)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return (0, "socket is not configured");

  switch (pr->type)
    {
    case PUNT_TYPE_L4:
      return (punt_socket_unregister_l4 (pr->punt.l4.af,
					 pr->punt.l4.protocol,
					 pr->punt.l4.port));
    case PUNT_TYPE_IP_PROTO:
      return (punt_socket_unregister_ip_proto (pr->punt.ip_proto.af,
					       pr->punt.ip_proto.protocol));
    case PUNT_TYPE_EXCEPTION:
      return (punt_socket_unregister_exception (pr->punt.exception.reason));
    }

  return 0;
}

/**
 * @brief Request IP L4 traffic punt to the local TCP/IP stack.
 *
 * @em Note
 * - UDP is the only protocol supported in the current implementation
 *
 * @param vm       vlib_main_t corresponding to the current thread
 * @param af       IP address family.
 * @param protocol 8-bits L4 protocol value
 *                 UDP is 17
 *                 TCP is 1
 * @param port     16-bits L4 (TCP/IP) port number when applicable (UDP only)
 *
 * @returns 0 on success, non-zero value otherwise
 */
static clib_error_t *
punt_l4_add_del (vlib_main_t * vm,
		 ip_address_family_t af,
		 ip_protocol_t protocol, u16 port, bool is_add)
{
  /* For now we only support TCP and UDP punt */
  if (protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_TCP)
    return clib_error_return (0,
			      "only UDP (%d) and TCP (%d) protocols are supported, got %d",
			      IP_PROTOCOL_UDP, IP_PROTOCOL_TCP, protocol);

  if (port == (u16) ~ 0)
    {
      if (protocol == IP_PROTOCOL_UDP)
	udp_punt_unknown (vm, af == AF_IP4, is_add);
      else if (protocol == IP_PROTOCOL_TCP)
	tcp_punt_unknown (vm, af == AF_IP4, is_add);

      return 0;
    }

  else if (is_add)
    {
      if (protocol == IP_PROTOCOL_TCP)
	return clib_error_return (0, "punt TCP ports is not supported yet");

      udp_register_dst_port (vm, port, udp4_punt_node.index, af == AF_IP4);

      return 0;
    }
  else
    {
      if (protocol == IP_PROTOCOL_TCP)
	return clib_error_return (0, "punt TCP ports is not supported yet");

      udp_unregister_dst_port (vm, port, af == AF_IP4);

      return 0;
    }
}

clib_error_t *
vnet_punt_add_del (vlib_main_t * vm, const punt_reg_t * pr, bool is_add)
{
  switch (pr->type)
    {
    case PUNT_TYPE_L4:
      return (punt_l4_add_del (vm, pr->punt.l4.af, pr->punt.l4.protocol,
			       pr->punt.l4.port, is_add));
    case PUNT_TYPE_EXCEPTION:
    case PUNT_TYPE_IP_PROTO:
      break;
    }

  return (clib_error_return (0, "Unsupported punt type: %d", pr->type));
}

static clib_error_t *
punt_cli (vlib_main_t * vm,
	  unformat_input_t * input__, vlib_cli_command_t * cmd)
{
  unformat_input_t line_input, *input = &line_input;
  clib_error_t *error = NULL;
  bool is_add = true;
  /* *INDENT-OFF* */
  punt_reg_t pr = {
    .punt = {
      .l4 = {
        .af = AF_IP4,
        .port = ~0,
        .protocol = IP_PROTOCOL_UDP,
      },
    },
    .type = PUNT_TYPE_L4,
  };
  u32 port;
  /* *INDENT-ON* */

  if (!unformat_user (input__, unformat_line_input, input))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = false;
      else if (unformat (input, "ipv4"))
	pr.punt.l4.af = AF_IP4;
      else if (unformat (input, "ipv6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "ip6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "%d", &port))
	pr.punt.l4.port = port;
      else if (unformat (input, "all"))
	pr.punt.l4.port = ~0;
      else if (unformat (input, "udp"))
	pr.punt.l4.protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	pr.punt.l4.protocol = IP_PROTOCOL_TCP;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  /* punt both IPv6 and IPv4 when used in CLI */
  error = vnet_punt_add_del (vm, &pr, is_add);
  if (error)
    {
      clib_error_report (error);
    }

done:
  unformat_free (input);
  return error;
}

/*?
 * The set of '<em>set punt</em>' commands allows specific IP traffic to
 * be punted to the host TCP/IP stack
 *
 * @em Note
 * - UDP is the only protocol supported in the current implementation
 * - All TCP traffic is currently punted to the host by default
 *
 * @cliexpar
 * @parblock
 * Example of how to request NTP traffic to be punted
 * @cliexcmd{set punt udp 125}
 *
 * Example of how to request all 'unknown' UDP traffic to be punted
 * @cliexcmd{set punt udp all}
 *
 * Example of how to stop all 'unknown' UDP traffic to be punted
 * @cliexcmd{set punt udp del all}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_command, static) = {
  .path = "set punt",
  .short_help = "set punt [IPV4|ip6|ipv6] [UDP|tcp] [del] [ALL|<port-num>]",
  .function = punt_cli,
};
/* *INDENT-ON* */

static clib_error_t *
punt_socket_register_cmd (vlib_main_t * vm,
			  unformat_input_t * input__,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t line_input, *input = &line_input;
  u8 *socket_name = 0;
  clib_error_t *error = NULL;
  /* *INDENT-OFF* */
  punt_reg_t pr = {
    .punt = {
      .l4 = {
        .af = AF_IP4,
        .port = ~0,
        .protocol = IP_PROTOCOL_UDP,
      },
    },
    .type = PUNT_TYPE_L4,
  };
  /* *INDENT-ON* */

  if (!unformat_user (input__, unformat_line_input, input))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ipv4"))
	pr.punt.l4.af = AF_IP4;
      else if (unformat (input, "ipv6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "udp"))
	pr.punt.l4.protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	pr.punt.l4.protocol = IP_PROTOCOL_TCP;
      else if (unformat (input, "%d", &pr.punt.l4.port))
	;
      else if (unformat (input, "all"))
	pr.punt.l4.port = ~0;
      else if (unformat (input, "socket %s", &socket_name))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (!socket_name)
    error = clib_error_return (0, "socket name not specified");
  else
    error = vnet_punt_socket_add (vm, 1, &pr, (char *) socket_name);

done:
  unformat_free (input);
  return error;
}

/*?
 *
 * @cliexpar
 * @cliexcmd{punt socket register socket punt_l4_foo.sock}

 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_socket_register_command, static) =
{
  .path = "punt socket register",
  .function = punt_socket_register_cmd,
  .short_help = "punt socket register [IPV4|ipv6] [UDP|tcp] [ALL|<port-num>] socket <socket>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
punt_socket_deregister_cmd (vlib_main_t * vm,
			    unformat_input_t * input__,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t line_input, *input = &line_input;
  clib_error_t *error = NULL;
  /* *INDENT-OFF* */
  punt_reg_t pr = {
    .punt = {
      .l4 = {
        .af = AF_IP4,
        .port = ~0,
        .protocol = IP_PROTOCOL_UDP,
      },
    },
    .type = PUNT_TYPE_L4,
  };
  /* *INDENT-ON* */

  if (!unformat_user (input__, unformat_line_input, input))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ipv4"))
	pr.punt.l4.af = AF_IP4;
      else if (unformat (input, "ipv6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "udp"))
	pr.punt.l4.protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	pr.punt.l4.protocol = IP_PROTOCOL_TCP;
      else if (unformat (input, "%d", &pr.punt.l4.port))
	;
      else if (unformat (input, "all"))
	pr.punt.l4.port = ~0;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  error = vnet_punt_socket_del (vm, &pr);
done:
  unformat_free (input);
  return error;
}

/*?
 *
 * @cliexpar
 * @cliexcmd{punt socket register}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_socket_deregister_command, static) =
{
  .path = "punt socket deregister",
  .function = punt_socket_deregister_cmd,
  .short_help = "punt socket deregister [IPV4|ipv6] [UDP|tcp] [ALL|<port-num>]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

void
punt_client_walk (punt_type_t pt, punt_client_walk_cb_t cb, void *ctx)
{
  punt_main_t *pm = &punt_main;

  switch (pt)
    {
    case PUNT_TYPE_L4:
      {
	u32 pci, key;

        /* *INDENT-OFF* */
        hash_foreach(key, pci, pm->db.clients_by_l4_port,
        ({
          cb (pool_elt_at_index(pm->punt_client_pool, pci), ctx);
        }));
        /* *INDENT-ON* */
	break;
      }
    case PUNT_TYPE_IP_PROTO:
      {
	u32 pci, key;

        /* *INDENT-OFF* */
        hash_foreach(key, pci, pm->db.clients_by_ip_proto,
        ({
          cb (pool_elt_at_index(pm->punt_client_pool, pci), ctx);
        }));
        /* *INDENT-ON* */
	break;
      }
    case PUNT_TYPE_EXCEPTION:
      {
	u32 *pci;

	vec_foreach (pci, pm->db.clients_by_exception)
	{
	  if (~0 != *pci)
	    cb (pool_elt_at_index (pm->punt_client_pool, *pci), ctx);
	}

	break;
      }
    }
}

static u8 *
format_punt_client (u8 * s, va_list * args)
{
  punt_client_t *pc = va_arg (*args, punt_client_t *);

  s = format (s, " punt ");

  switch (pc->reg.type)
    {
    case PUNT_TYPE_L4:
      s = format (s, "%U %U port %d",
		  format_ip_address_family, pc->reg.punt.l4.af,
		  format_ip_protocol, pc->reg.punt.l4.protocol,
		  pc->reg.punt.l4.port);
      break;
    case PUNT_TYPE_IP_PROTO:
      s = format (s, "%U %U",
		  format_ip_address_family, pc->reg.punt.ip_proto.af,
		  format_ip_protocol, pc->reg.punt.ip_proto.protocol);
      break;
    case PUNT_TYPE_EXCEPTION:
      s = format (s, " %U", format_vlib_punt_reason,
		  pc->reg.punt.exception.reason);
      break;
    }

  s = format (s, " to socket %s \n", pc->caddr.sun_path);

  return (s);
}

static walk_rc_t
punt_client_show_one (const punt_client_t * pc, void *ctx)
{
  vlib_cli_output (ctx, "%U", format_punt_client, pc);

  return (WALK_CONTINUE);
}

static clib_error_t *
punt_socket_show_cmd (vlib_main_t * vm,
		      unformat_input_t * input__, vlib_cli_command_t * cmd)
{
  unformat_input_t line_input, *input = &line_input;
  clib_error_t *error = NULL;
  punt_type_t pt;

  pt = PUNT_TYPE_L4;

  if (!unformat_user (input__, unformat_line_input, input))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "exception"))
	pt = PUNT_TYPE_EXCEPTION;
      else if (unformat (input, "l4"))
	pt = PUNT_TYPE_L4;
      else if (unformat (input, "ip"))
	pt = PUNT_TYPE_IP_PROTO;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  punt_client_walk (pt, punt_client_show_one, vm);

done:
  unformat_free (input);
  return (error);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{show punt socket ipv4}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_punt_socket_registration_command, static) =
{
  .path = "show punt socket registrations",
  .function = punt_socket_show_cmd,
  .short_help = "show punt socket registrations [l4|exception]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
ip_punt_init (vlib_main_t * vm)
{
  clib_error_t *error = NULL;
  punt_main_t *pm = &punt_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  pm->is_configured = false;
  pm->interface_output_node =
    vlib_get_node_by_name (vm, (u8 *) "interface-output");

  if ((error = vlib_call_init_function (vm, punt_init)))
    return error;

  pm->hdl = vlib_punt_client_register ("ip-punt");

  vec_validate_aligned (pm->thread_data, tm->n_vlib_mains,
			CLIB_CACHE_LINE_BYTES);

  return (error);
}

VLIB_INIT_FUNCTION (ip_punt_init);

static clib_error_t *
punt_config (vlib_main_t * vm, unformat_input_t * input)
{
  punt_main_t *pm = &punt_main;
  char *socket_path = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket %s", &socket_path))
	strncpy (pm->sun_path, socket_path, UNIX_PATH_MAX - 1);
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (socket_path == 0)
    return 0;

  /* UNIX domain socket */
  struct sockaddr_un addr;
  if ((pm->socket_fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1)
    {
      return clib_error_return (0, "socket error");
    }

  clib_memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  if (*socket_path == '\0')
    {
      *addr.sun_path = '\0';
      strncpy (addr.sun_path + 1, socket_path + 1,
	       sizeof (addr.sun_path) - 2);
    }
  else
    {
      strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path) - 1);
      unlink (socket_path);
    }

  if (bind (pm->socket_fd, (struct sockaddr *) &addr, sizeof (addr)) == -1)
    {
      return clib_error_return (0, "bind error");
    }

  int n_bytes = 0x10000;

  if (setsockopt
      (pm->socket_fd, SOL_SOCKET, SO_SNDBUF, &n_bytes,
       sizeof (n_bytes)) == -1)
    {
      return clib_error_return (0, "setsockopt error");
    }

  /* Register socket */
  clib_file_main_t *fm = &file_main;
  clib_file_t template = { 0 };
  template.read_function = punt_socket_read_ready;
  template.file_descriptor = pm->socket_fd;
  template.description = format (0, "punt socket %s", socket_path);
  pm->clib_file_index = clib_file_add (fm, &template);

  pm->is_configured = true;

  return 0;
}

VLIB_CONFIG_FUNCTION (punt_config, "punt");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
