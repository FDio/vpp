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

#include <npol/npol.h>
#include <npol/npol_ipset.h>

npol_ipset_t *npol_ipsets;

u8 *
format_npol_ipport (u8 *s, va_list *args)
{
  npol_ipport_t *ipport = va_arg (*args, npol_ipport_t *);
  return format (s, "%U %U;%u", format_ip_protocol, ipport->l4proto,
		 format_ip_address, &ipport->addr, ipport->port);
}

u8 *
format_npol_ipset_member (u8 *s, va_list *args)
{
  npol_ipset_member_t *member = va_arg (*args, npol_ipset_member_t *);
  npol_ipset_type_t type = va_arg (*args, npol_ipset_type_t);
  switch (type)
    {
    case IPSET_TYPE_IP:
      return format (s, "%U", format_ip_address, &member->address);
    case IPSET_TYPE_IPPORT:
      return format (s, "%U", format_npol_ipport, &member->ipport);
    case IPSET_TYPE_NET:
      return format (s, "%U", format_ip_prefix, &member->prefix);
    default:
      return format (s, "unknown type");
    }
}

uword
unformat_npol_ipport (unformat_input_t *input, va_list *args)
{
  npol_ipport_t *ipport = va_arg (*args, npol_ipport_t *);
  u32 proto;
  u32 port;
  if (unformat (input, "%U %U %d", unformat_ip_protocol, &proto,
		unformat_ip_address, &ipport->addr, &port))
    ;
  else
    return 0;

  ipport->port = port;
  ipport->l4proto = (u8) proto;
  return 1;
}

u8 *
format_npol_ipset_type (u8 *s, va_list *args)
{
  npol_ipset_type_t type = va_arg (*args, npol_ipset_type_t);
  switch (type)
    {
    case IPSET_TYPE_IP:
      return format (s, "ip");
    case IPSET_TYPE_IPPORT:
      return format (s, "ip+port");
    case IPSET_TYPE_NET:
      return format (s, "prefix");
    default:
      return format (s, "unknownipsettype");
    }
}

uword
unformat_npol_ipset_member (unformat_input_t *input, va_list *args)
{
  npol_ipset_member_t *member = va_arg (*args, npol_ipset_member_t *);
  npol_ipset_type_t *type = va_arg (*args, npol_ipset_type_t *);
  if (unformat_user (input, unformat_ip_prefix, &member->prefix))
    *type = IPSET_TYPE_NET;
  else if (unformat_user (input, unformat_ip_address, &member->address))
    *type = IPSET_TYPE_IP;
  else if (unformat_user (input, unformat_npol_ipport, &member->ipport))
    *type = IPSET_TYPE_IPPORT;
  else
    return 0;

  return 1;
}

u8 *
format_npol_ipset (u8 *s, va_list *args)
{
  npol_ipset_t *ipset = va_arg (*args, npol_ipset_t *);
  npol_ipset_member_t *member;

  if (ipset == NULL)
    return format (s, "deleted ipset");

  s = format (s, "[ipset#%d;%U;", ipset - npol_ipsets, format_npol_ipset_type,
	      ipset->type);

  pool_foreach (member, ipset->members)
    s = format (s, "%U,", format_npol_ipset_member, member, ipset->type);

  s = format (s, "]");

  return (s);
}

npol_ipset_t *
npol_ipsets_get_if_exists (u32 index)
{
  if (pool_is_free_index (npol_ipsets, index))
    return (NULL);
  return pool_elt_at_index (npol_ipsets, index);
}

u32
npol_ipset_create (npol_ipset_type_t type)
{
  npol_ipset_t *ipset;
  pool_get (npol_ipsets, ipset);
  ipset->type = type;
  ipset->members = NULL;
  return ipset - npol_ipsets;
}

int
npol_ipset_delete (u32 id)
{
  npol_ipset_t *ipset;
  ipset = npol_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_free (ipset->members);
  pool_put (npol_ipsets, ipset);
  return 0;
}

int
npol_ipset_get_type (u32 id, npol_ipset_type_t *type)
{
  npol_ipset_t *ipset;
  ipset = npol_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *type = ipset->type;
  return 0;
}

int
npol_ipset_add_member (u32 ipset_id, npol_ipset_member_t *member)
{
  npol_ipset_member_t *m;
  npol_ipset_t *ipset = &npol_ipsets[ipset_id];

  if (pool_is_free (npol_ipsets, ipset))
    {
      return 1;
    }

  /* zero so that we can memcmp later */
  pool_get_zero (ipset->members, m);
  clib_memcpy (m, member, sizeof (*m));
  return 0;
}

static size_t
npol_ipset_member_cmp (npol_ipset_member_t *m1, npol_ipset_member_t *m2,
		       npol_ipset_type_t type)
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
npol_ipset_del_member (u32 id, npol_ipset_member_t *member)
{
  index_t *index, *indexes = NULL;
  npol_ipset_member_t *m;
  npol_ipset_t *ipset;

  ipset = npol_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_foreach (m, ipset->members)
    {
      if (!npol_ipset_member_cmp (m, member, ipset->type))
	vec_add1 (indexes, m - ipset->members);
    }

  vec_foreach (index, indexes)
    pool_put_index (ipset->members, *index);
  vec_free (indexes);

  return 0;
}

static clib_error_t *
npol_ipsets_show_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  npol_ipset_t *ipset;

  pool_foreach (ipset, npol_ipsets)
    vlib_cli_output (vm, "%U", format_npol_ipset, ipset);

  return 0;
}

VLIB_CLI_COMMAND (npol_ipsets_show_cmd, static) = {
  .path = "show npol ipsets",
  .function = npol_ipsets_show_cmd_fn,
  .short_help = "show npol ipsets",
};

static clib_error_t *
npol_ipsets_add_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  npol_ipset_member_t tmp, *members = 0, *member;
  clib_error_t *error = 0;
  npol_ipset_type_t type;
  npol_ipset_t *ipset;
  u32 id;
  int rv;

  id = npol_ipset_create ((npol_ipset_type_t) ~0);
  vlib_cli_output (vm, "npol ipset %d added", id);

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_npol_ipset_member, &tmp, &type))
	vec_add1 (members, tmp);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  ipset = pool_elt_at_index (npol_ipsets, id);
  ipset->type = type;

  vec_foreach (member, members)
    {
      rv = npol_ipset_add_member (id, member);
      if (rv)
	error = clib_error_return (0, "npol_ipset_add_member error %d", rv);
    }

done:
  vec_free (members);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_ipsets_add_cmd, static) = {
  .path = "npol ipset add",
  .function = npol_ipsets_add_cmd_fn,
  .short_help = "npol ipset add [prefix|proto ip port|ip]",
};

static clib_error_t *
npol_ipsets_del_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = NPOL_INVALID_INDEX;
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

  if (NPOL_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing ipset id");
      goto done;
    }

  rv = npol_ipset_delete (id);
  if (rv)
    error = clib_error_return (0, "npol_ipset_delete errored with %d", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_ipsets_del_cmd, static) = {
  .path = "npol ipset del",
  .function = npol_ipsets_del_cmd_fn,
  .short_help = "npol ipset del [id]",
};

static clib_error_t *
npol_ipsets_add_member_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  npol_ipset_member_t tmp, *members = 0, *member;
  u32 id = NPOL_INVALID_INDEX;
  clib_error_t *error = 0;
  npol_ipset_type_t type;
  npol_ipset_t *ipset;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %u", &id))
	;
      else if (unformat (line_input, "%U", unformat_npol_ipset_member, &tmp,
			 &type))
	vec_add1 (members, tmp);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (NPOL_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing ipset id");
      goto done;
    }

  ipset = npol_ipsets_get_if_exists (id);
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
      rv = npol_ipset_add_member (id, member);
      if (rv)
	error = clib_error_return (0, "npol_ipset_add_member error %d", rv);
    }

done:
  vec_free (members);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_ipsets_add_member_cmd, static) = {
  .path = "npol ipset add member",
  .function = npol_ipsets_add_member_cmd_fn,
  .short_help = "npol ipset add member [id] [prefix]",
};

static clib_error_t *
npol_ipsets_del_member_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 id = NPOL_INVALID_INDEX;
  npol_ipset_type_t type;
  npol_ipset_member_t tmp, *members = 0, *member;
  npol_ipset_t *ipset;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing parameters");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %u", &id))
	;
      else if (unformat (line_input, "%U", unformat_npol_ipset_member, &tmp,
			 &type))
	vec_add1 (members, tmp);
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (NPOL_INVALID_INDEX == id)
    {
      error = clib_error_return (0, "missing ipset id");
      goto done;
    }

  ipset = npol_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return clib_error_return (0, "ipset not found");
  if (ipset->type != type)
    {
      error = clib_error_return (0, "wrong member type");
      goto done;
    }

  vec_foreach (member, members)
    {
      rv = npol_ipset_del_member (id, member);
      if (rv)
	error =
	  clib_error_return (0, "npol_ipset_del_member errored with %d", rv);
    }

done:
  vec_free (members);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (npol_ipsets_del_member_cmd, static) = {
  .path = "npol ipset del member",
  .function = npol_ipsets_del_member_cmd_fn,
  .short_help = "npol ipset del member [id] [prefix]",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
