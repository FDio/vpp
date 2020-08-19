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


#include <capo/capo.h>
#include <capo/capo_ipset.h>

capo_ipset_t *capo_ipsets;

u8 *
format_capo_ipport (u8 * s, va_list * args)
{
  capo_ipport_t *ipport = va_arg (*args, capo_ipport_t *);
  return format (s, "%U %U;%u",
		 format_ip_protocol, ipport->l4proto,
		 format_ip_address, &ipport->addr, ipport->port);
}

u8 *
format_capo_ipset_member (u8 * s, va_list * args)
{
  capo_ipset_member_t *member = va_arg (*args, capo_ipset_member_t *);
  capo_ipset_type_t type = va_arg (*args, capo_ipset_type_t);
  switch (type)
    {
    case IPSET_TYPE_IP:
      return format (s, "%U", format_ip_address, &member->address);
    case IPSET_TYPE_IPPORT:
      return format (s, "%U", format_capo_ipport, &member->ipport);
    case IPSET_TYPE_NET:
      return format (s, "%U", format_ip_prefix, &member->prefix);
    default:
      return format (s, "unknown type");
    }
}

uword
unformat_capo_ipport (unformat_input_t * input, va_list * args)
{
  capo_ipport_t *ipport = va_arg (*args, capo_ipport_t *);
  u32 proto;
  u32 port;
  if (unformat (input, "%U %U %d",
		unformat_ip_protocol, &proto,
		unformat_ip_address, &ipport->addr, &port))
    ;
  else
    return 0;

  ipport->port = port;
  ipport->l4proto = (u8) proto;
  return 1;
}

u8 *
format_capo_ipset_type (u8 * s, va_list * args)
{
  capo_ipset_type_t type = va_arg (*args, capo_ipset_type_t);
  switch (type)
    {
    case IPSET_TYPE_IP:
      return format (s, "ip");
    case IPSET_TYPE_IPPORT:
      return format (s, "ip+port");
    case IPSET_TYPE_NET:
      return format (s, "prefix");
    default:
      return format (s, "unknown");
    }
}

uword
unformat_capo_ipset_member (unformat_input_t * input, va_list * args)
{
  capo_ipset_member_t *member = va_arg (*args, capo_ipset_member_t *);
  capo_ipset_type_t *type = va_arg (*args, capo_ipset_type_t *);
  if (unformat_user (input, unformat_ip_prefix, &member->prefix))
    *type = IPSET_TYPE_NET;
  else if (unformat_user (input, unformat_ip_address, &member->address))
    *type = IPSET_TYPE_IP;
  else if (unformat_user (input, unformat_capo_ipport, &member->ipport))
    *type = IPSET_TYPE_IPPORT;
  else
    return 0;

  return 1;
}

u8 *
format_capo_ipset (u8 * s, va_list * args)
{
  capo_ipset_t *ipset = va_arg (*args, capo_ipset_t *);
  capo_ipset_member_t *member;

  s =
    format (s, "[%d] %U\n", ipset - capo_ipsets, format_capo_ipset_type,
	    ipset->type);

  /* *INDENT-OFF* */
  pool_foreach (member, ipset->members, ({
    s = format (s, "  %U\n", format_capo_ipset_member, member, ipset->type);
  }));
  /* *INDENT-ON* */

  return (s);
}

static capo_ipset_t *
capo_ipsets_get_if_exists (u32 index)
{
  if (pool_is_free_index (capo_ipsets, index))
    return (NULL);
  return pool_elt_at_index (capo_ipsets, index);
}

u32
capo_ipset_create (capo_ipset_type_t type)
{
  capo_ipset_t *ipset;
  pool_get (capo_ipsets, ipset);
  ipset->type = type;
  ipset->members = NULL;
  return ipset - capo_ipsets;
}

int
capo_ipset_delete (u32 id)
{
  capo_ipset_t *ipset;
  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_free (ipset->members);
  pool_put (capo_ipsets, ipset);
  return 0;
}

int
capo_ipset_get_type (u32 id, capo_ipset_type_t * type)
{
  capo_ipset_t *ipset;
  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *type = ipset->type;
  return 0;
}

int
capo_ipset_add_member (u32 ipset_id, capo_ipset_member_t * member)
{
  capo_ipset_member_t *m;
  capo_ipset_t *ipset = &capo_ipsets[ipset_id];

  if (pool_is_free (capo_ipsets, ipset))
    {
      return 1;
    }

  /* zero so that we can memcmp later */
  pool_get_zero (ipset->members, m);
  clib_memcpy (m, member, sizeof (*m));
  return 0;
}

static size_t
capo_ipset_member_cmp (capo_ipset_member_t * m1, capo_ipset_member_t * m2,
		       capo_ipset_type_t type)
{
  switch (type)
    {
    case IPSET_TYPE_IP:
      return ip_address_cmp (&m1->address, &m2->address);
    case IPSET_TYPE_IPPORT:
      return ((m1->ipport.port == m2->ipport.port) &&
	      (m1->ipport.l4proto == m2->ipport.l4proto) &&
	      ip_address_cmp (&m1->ipport.addr, &m2->ipport.addr));
    case IPSET_TYPE_NET:
      return ip_prefix_cmp (&m1->prefix, &m2->prefix);
    default:
      return 1;
    }
}

int
capo_ipset_del_member (u32 id, capo_ipset_member_t * member)
{
  index_t *index, *indexes = NULL;
  capo_ipset_member_t *m;
  capo_ipset_t *ipset;

  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* *INDENT-OFF* */
  pool_foreach(m, ipset->members, ({
    if (!capo_ipset_member_cmp (m, member, ipset->type))
      vec_add1 (indexes, m - ipset->members);
  }));
  /* *INDENT-ON* */

  vec_foreach (index, indexes) pool_put_index (ipset->members, *index);
  vec_free (indexes);

  return 0;
}

static clib_error_t *
capo_ipsets_show_cmd_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  capo_ipset_t *ipset;

  /* *INDENT-OFF* */
  pool_foreach (ipset, capo_ipsets, ({
    vlib_cli_output (vm, "%U", format_capo_ipset, ipset);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_ipsets_show_cmd, static) = {
  .path = "show capo ipsets",
  .function = capo_ipsets_show_cmd_fn,
  .short_help = "show capo ipsets",
};
/* *INDENT-ON* */

static clib_error_t *
capo_ipsets_add_cmd_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  capo_ipset_member_t tmp, *members = 0, *member;
  clib_error_t *error = 0;
  capo_ipset_type_t type;
  capo_ipset_t *ipset;
  u32 id;
  int rv;

  id = capo_ipset_create ((capo_ipset_type_t) ~ 0);
  vlib_cli_output (vm, "capo ipset %d added", id);

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_capo_ipset_member, &tmp, &type))
	vec_add1 (members, tmp);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  ipset = pool_elt_at_index (capo_ipsets, id);
  ipset->type = type;

  vec_foreach (member, members)
  {
    rv = capo_ipset_add_member (id, member);
    if (rv)
      error = clib_error_return (0, "capo_ipset_add_member error %d", rv);
  }

done:
  vec_free (members);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_ipsets_add_cmd, static) = {
  .path = "capo ipset add",
  .function = capo_ipsets_add_cmd_fn,
  .short_help = "capo ipset add [prefix|proto ip port|ip]",
};
/* *INDENT-ON* */


static clib_error_t *
capo_ipsets_del_cmd_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = CAPO_INVALID_INDEX;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing ipset id");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (CAPO_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing ipset id");
      goto done;
    }

  rv = capo_ipset_delete (id);
  if (rv)
    error = clib_error_return (0, "capo_ipset_delete errored with %d", rv);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_ipsets_del_cmd, static) = {
  .path = "capo ipset del",
  .function = capo_ipsets_del_cmd_fn,
  .short_help = "capo ipset del [id]",
};
/* *INDENT-ON* */

static clib_error_t *
capo_ipsets_add_member_cmd_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  capo_ipset_member_t tmp, *members = 0, *member;
  u32 id = CAPO_INVALID_INDEX;
  clib_error_t *error = 0;
  capo_ipset_type_t type;
  capo_ipset_t *ipset;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %u", &id))
	;
      else
	if (unformat (line_input, "%U",
		      unformat_capo_ipset_member, &tmp, &type))
	vec_add1 (members, tmp);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (CAPO_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing ipset id");
      goto done;
    }

  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return clib_error_return (0, "ipset not found");
  if (ipset->type != type && ~0 != ipset->type)
    {
      error = clib_error_return (0, "cannot change ipset type");
      goto done;
    }
  ipset->type = type;

  vec_foreach (member, members)
  {
    rv = capo_ipset_add_member (id, member);
    if (rv)
      error = clib_error_return (0, "capo_ipset_add_member error %d", rv);
  }


done:
  vec_free (members);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_ipsets_add_member_cmd, static) = {
  .path = "capo ipset add member",
  .function = capo_ipsets_add_member_cmd_fn,
  .short_help = "capo ipset add member [id] [prefix]",
};
/* *INDENT-ON* */

static clib_error_t *
capo_ipsets_del_member_cmd_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = CAPO_INVALID_INDEX;
  capo_ipset_type_t type;
  capo_ipset_member_t tmp, *members = 0, *member;
  capo_ipset_t *ipset;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %u", &id))
	;
      else
	if (unformat
	    (line_input, "%U", unformat_capo_ipset_member, &tmp, &type))
	vec_add1 (members, tmp);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (CAPO_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing ipset id");
      goto done;
    }

  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return clib_error_return (0, "ipset not found");
  if (ipset->type != type)
    {
      error = clib_error_return (0, "wrong member type");
      goto done;
    }

  vec_foreach (member, members)
  {
    rv = capo_ipset_del_member (id, member);
    if (rv)
      error =
	clib_error_return (0, "capo_ipset_del_member errored with %d", rv);
  }


done:
  vec_free (members);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (capo_ipsets_del_member_cmd, static) = {
  .path = "capo ipset del member",
  .function = capo_ipsets_del_member_cmd_fn,
  .short_help = "capo ipset del member [id] [prefix]",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
