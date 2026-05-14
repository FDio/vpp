/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <tlspicotls/tls_picotls.h>

int
picotls_alpn_list_to_iovecs (u8 *alpn_list, ptls_iovec_t **iovecs)
{
  size_t offset = 0;

  while (offset < vec_len (alpn_list))
    {
      ptls_iovec_t *proto;
      u8 proto_len = alpn_list[offset++];

      if (offset + proto_len > vec_len (alpn_list))
	{
	  vec_free (*iovecs);
	  return -1;
	}

      vec_add2 (*iovecs, proto, 1);
      proto->base = alpn_list + offset;
      proto->len = proto_len;
      offset += proto_len;
    }

  return vec_len (*iovecs);
}

int
picotls_select_alpn_proto (u8 *server_alpn_list, ptls_iovec_t *client_alpn_list,
			   size_t client_alpn_count, u8 **selected_proto, u8 *selected_proto_len)
{
  size_t offset = 0;

  *selected_proto = 0;
  *selected_proto_len = 0;

  if (!client_alpn_count || !server_alpn_list)
    return 0;

  while (offset < vec_len (server_alpn_list))
    {
      u8 *server_proto;
      u8 server_proto_len = server_alpn_list[offset++];

      if (offset + server_proto_len > vec_len (server_alpn_list))
	return -1;

      server_proto = server_alpn_list + offset;
      for (size_t i = 0; i < client_alpn_count; i++)
	{
	  if (server_proto_len != client_alpn_list[i].len)
	    continue;
	  if (clib_memcmp (server_proto, client_alpn_list[i].base, server_proto_len))
	    continue;

	  *selected_proto = server_proto;
	  *selected_proto_len = server_proto_len;
	  return 1;
	}
      offset += server_proto_len;
    }

  return 0;
}
