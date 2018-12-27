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
#include <vnet/session/application_interface.h>

#include <vnet/session/session.h>
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>

/** @file
    VPP's application/session API bind/unbind/connect/disconnect calls
*/

/*
 * TLS server cert and keys to be used for testing only
 */
const char test_srv_crt_rsa[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIID5zCCAs+gAwIBAgIJALeMYCEHrTtJMA0GCSqGSIb3DQEBCwUAMIGJMQswCQYD\r\n"
  "VQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMQ4wDAYDVQQK\r\n"
  "DAVDaXNjbzEOMAwGA1UECwwFZmQuaW8xFjAUBgNVBAMMDXRlc3R0bHMuZmQuaW8x\r\n"
  "IjAgBgkqhkiG9w0BCQEWE3ZwcC1kZXZAbGlzdHMuZmQuaW8wHhcNMTgwMzA1MjEx\r\n"
  "NTEyWhcNMjgwMzAyMjExNTEyWjCBiTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB\r\n"
  "MREwDwYDVQQHDAhTYW4gSm9zZTEOMAwGA1UECgwFQ2lzY28xDjAMBgNVBAsMBWZk\r\n"
  "LmlvMRYwFAYDVQQDDA10ZXN0dGxzLmZkLmlvMSIwIAYJKoZIhvcNAQkBFhN2cHAt\r\n"
  "ZGV2QGxpc3RzLmZkLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
  "4C1k8a1DuStgggqT4o09fP9sJ2dC54bxhS/Xk2VEfaIZ222WSo4X/syRVfVy9Yah\r\n"
  "cpI1zJ/RDxaZSFhgA+nPZBrFMsrULkrdAOpOVj8eDEp9JuWdO2ODSoFnCvLxcYWB\r\n"
  "Yc5kHryJpEaGJl1sFQSesnzMFty/59ta0stk0Fp8r5NhIjWvSovGzPo6Bhz+VS2c\r\n"
  "ebIZh4x1t2hHaFcgm0qJoJ6DceReWCW8w+yOVovTolGGq+bpb2Hn7MnRSZ2K2NdL\r\n"
  "+aLXpkZbS/AODP1FF2vTO1mYL290LO7/51vJmPXNKSDYMy5EvILr5/VqtjsFCwRL\r\n"
  "Q4jcM/+GeHSAFWx4qIv0BwIDAQABo1AwTjAdBgNVHQ4EFgQUWa1SOB37xmT53tZQ\r\n"
  "aXuLLhRI7U8wHwYDVR0jBBgwFoAUWa1SOB37xmT53tZQaXuLLhRI7U8wDAYDVR0T\r\n"
  "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoUht13W4ya27NVzQuCMvqPWL3VM4\r\n"
  "3xbPFk02FaGz/WupPu276zGlzJAZrbuDcQowwwU1Ni1Yygxl96s1c2M5rHDTrOKG\r\n"
  "rK0hbkSFBo+i6I8u4HiiQ4rYmG0Hv6+sXn3of0HsbtDPGgWZoipPWDljPYEURu3e\r\n"
  "3HRe/Dtsj9CakBoSDzs8ndWaBR+f4sM9Tk1cjD46Gq2T/qpSPXqKxEUXlzhdCAn4\r\n"
  "twub17Bq2kykHpppCwPg5M+v30tHG/R2Go15MeFWbEJthFk3TZMjKL7UFs7fH+x2\r\n"
  "wSonXb++jY+KmCb93C+soABBizE57g/KmiR2IxQ/LMjDik01RSUIaM0lLA==\r\n"
  "-----END CERTIFICATE-----\r\n";
const u32 test_srv_crt_rsa_len = sizeof (test_srv_crt_rsa);

const char test_srv_key_rsa[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDgLWTxrUO5K2CC\r\n"
  "CpPijT18/2wnZ0LnhvGFL9eTZUR9ohnbbZZKjhf+zJFV9XL1hqFykjXMn9EPFplI\r\n"
  "WGAD6c9kGsUyytQuSt0A6k5WPx4MSn0m5Z07Y4NKgWcK8vFxhYFhzmQevImkRoYm\r\n"
  "XWwVBJ6yfMwW3L/n21rSy2TQWnyvk2EiNa9Ki8bM+joGHP5VLZx5shmHjHW3aEdo\r\n"
  "VyCbSomgnoNx5F5YJbzD7I5Wi9OiUYar5ulvYefsydFJnYrY10v5otemRltL8A4M\r\n"
  "/UUXa9M7WZgvb3Qs7v/nW8mY9c0pINgzLkS8guvn9Wq2OwULBEtDiNwz/4Z4dIAV\r\n"
  "bHioi/QHAgMBAAECggEBAMzGipP8+oT166U+NlJXRFifFVN1DvdhG9PWnOxGL+c3\r\n"
  "ILmBBC08WQzmHshPemBvR6DZkA1H23cV5JTiLWrFtC00CvhXsLRMrE5+uWotI6yE\r\n"
  "iofybMroHvD6/X5R510UX9hQ6MHu5ShLR5VZ9zXHz5MpTmB/60jG5dLx+jgcwBK8\r\n"
  "LuGv2YB/WCUwT9QJ3YU2eaingnXtz/MrFbkbltrqlnBdlD+kTtw6Yac9y1XuuQXc\r\n"
  "BPeulLNDuPolJVWbUvDBZrpt2dXTgz8ws1sv+wCNE0xwQJsqW4Nx3QkpibUL9RUr\r\n"
  "CVbKlNfa9lopT6nGKlgX69R/uH35yh9AOsfasro6w0ECgYEA82UJ8u/+ORah+0sF\r\n"
  "Q0FfW5MTdi7OAUHOz16pUsGlaEv0ERrjZxmAkHA/VRwpvDBpx4alCv0Hc39PFLIk\r\n"
  "nhSsM2BEuBkTAs6/GaoNAiBtQVE/hN7awNRWVmlieS0go3Y3dzaE9IUMyj8sPOFT\r\n"
  "5JdJ6BM69PHKCkY3dKdnnfpFEuECgYEA68mRpteunF1mdZgXs+WrN+uLlRrQR20F\r\n"
  "ZyMYiUCH2Dtn26EzA2moy7FipIIrQcX/j+KhYNGM3e7MU4LymIO29E18mn8JODnH\r\n"
  "sQOXzBTsf8A4yIVMkcuQD3bfb0JiUGYUPOidTp2N7IJA7+6Yc3vQOyb74lnKnJoO\r\n"
  "gougPT2wS+cCgYAn7muzb6xFsXDhyW0Tm6YJYBfRS9yAWEuVufINobeBZPSl2cN1\r\n"
  "Jrnw+HlrfTNbrJWuJmjtZJXUXQ6cVp2rUbjutNyRV4vG6iRwEXYQ40EJdkr1gZpi\r\n"
  "CHQhuShuuPih2MNAy7EEbM+sXrDjTBR3bFqzuHPzu7dp+BshCFX3lRfAAQKBgGQt\r\n"
  "K5i7IhCFDjb/+3IPLgOAK7mZvsvZ4eXD33TQ2eZgtut1PXtBtNl17/b85uv293Fm\r\n"
  "VDISVcsk3eLNS8zIiT6afUoWlxAwXEs0v5WRfjl4radkGvgGiJpJYvyeM67877RB\r\n"
  "EDSKc/X8ESLfOB44iGvZUEMG6zJFscx9DgN25iQZAoGAbyd+JEWwdVH9/K3IH1t2\r\n"
  "PBkZX17kNWv+iVM1WyFjbe++vfKZCrOJiyiqhDeEqgrP3AuNMlaaduC3VRC3G5oV\r\n"
  "Mj1tlhDWQ/qhvKdCKNdIVQYDE75nw+FRWV8yYkHAnXYW3tNoweDIwixE0hkPR1bc\r\n"
  "oEjPLVNtx8SOj/M4rhaPT3I=\r\n" "-----END PRIVATE KEY-----\r\n";
const u32 test_srv_key_rsa_len = sizeof (test_srv_key_rsa);

#define app_interface_check_thread_and_barrier(_fn, _arg)		\
  if (PREDICT_FALSE (!vlib_thread_is_main_w_barrier ()))		\
    {									\
      vlib_rpc_call_main_thread (_fn, (u8 *) _arg, sizeof(*_arg));	\
      return 0;								\
    }

static u8
session_endpoint_is_local (session_endpoint_t * sep)
{
  return (ip_is_zero (&sep->ip, sep->is_ip4)
	  || ip_is_local_host (&sep->ip, sep->is_ip4));
}

static u8
session_endpoint_is_zero (session_endpoint_t * sep)
{
  return ip_is_zero (&sep->ip, sep->is_ip4);
}

u8
session_endpoint_in_ns (session_endpoint_t * sep)
{
  u8 is_lep = session_endpoint_is_local (sep);
  if (!is_lep && sep->sw_if_index != ENDPOINT_INVALID_INDEX
      && !ip_interface_has_address (sep->sw_if_index, &sep->ip, sep->is_ip4))
    {
      clib_warning ("sw_if_index %u not configured with ip %U",
		    sep->sw_if_index, format_ip46_address, &sep->ip,
		    sep->is_ip4);
      return 0;
    }
  return (is_lep || ip_is_local (sep->fib_index, &sep->ip, sep->is_ip4));
}

int
api_parse_session_handle (u64 handle, u32 * session_index, u32 * thread_index)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  stream_session_t *pool;

  *thread_index = handle & 0xFFFFFFFF;
  *session_index = handle >> 32;

  if (*thread_index >= vec_len (smm->wrk))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = smm->wrk[*thread_index].sessions;

  if (pool_is_free_index (pool, *session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  return 0;
}

static void
session_endpoint_update_for_app (session_endpoint_cfg_t * sep,
				 application_t * app, u8 is_connect)
{
  app_namespace_t *app_ns;
  u32 ns_index, fib_index;

  ns_index = app->ns_index;

  /* App is a transport proto, so fetch the calling app's ns */
  if (app->flags & APP_OPTIONS_FLAGS_IS_TRANSPORT_APP)
    {
      app_worker_t *owner_wrk;
      application_t *owner_app;

      owner_wrk = app_worker_get (sep->app_wrk_index);
      owner_app = application_get (owner_wrk->app_index);
      ns_index = owner_app->ns_index;
    }
  app_ns = app_namespace_get (ns_index);
  if (!app_ns)
    return;

  /* Ask transport and network to bind to/connect using local interface
   * that "supports" app's namespace. This will fix our local connection
   * endpoint.
   */

  /* If in default namespace and user requested a fib index use it */
  if (ns_index == 0 && sep->fib_index != ENDPOINT_INVALID_INDEX)
    fib_index = sep->fib_index;
  else
    fib_index = sep->is_ip4 ? app_ns->ip4_fib_index : app_ns->ip6_fib_index;
  sep->peer.fib_index = fib_index;
  sep->fib_index = fib_index;

  if (!is_connect)
    {
      sep->sw_if_index = app_ns->sw_if_index;
    }
  else
    {
      if (app_ns->sw_if_index != APP_NAMESPACE_INVALID_INDEX
	  && sep->peer.sw_if_index != ENDPOINT_INVALID_INDEX
	  && sep->peer.sw_if_index != app_ns->sw_if_index)
	clib_warning ("Local sw_if_index different from app ns sw_if_index");

      sep->peer.sw_if_index = app_ns->sw_if_index;
    }
}

static inline int
vnet_bind_inline (vnet_bind_args_t * a)
{
  u64 ll_handle = SESSION_INVALID_HANDLE;
  app_worker_t *app_wrk;
  application_t *app;
  int rv;

  app = application_get_if_valid (a->app_index);
  if (!app)
    {
      SESSION_DBG ("app not attached");
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }
  app_wrk = application_get_worker (app, a->wrk_map_index);
  a->sep_ext.app_wrk_index = app_wrk->wrk_index;

  session_endpoint_update_for_app (&a->sep_ext, app, 0 /* is_connect */ );
  if (!session_endpoint_in_ns (&a->sep))
    return VNET_API_ERROR_INVALID_VALUE_2;

  /*
   * Add session endpoint to local session table. Only binds to "inaddr_any"
   * (i.e., zero address) are added to local scope table.
   */
  if (application_has_local_scope (app)
      && session_endpoint_is_local (&a->sep))
    {
      if ((rv = application_start_local_listen (app, &a->sep_ext,
						&a->handle)))
	return rv;
      ll_handle = a->handle;
    }

  if (!application_has_global_scope (app))
    return (ll_handle == SESSION_INVALID_HANDLE ? -1 : 0);

  /*
   * Add session endpoint to global session table
   */

  /* Setup listen path down to transport */
  rv = application_start_listen (app, &a->sep_ext, &a->handle);
  if (rv && ll_handle != SESSION_INVALID_HANDLE)
    {
      application_stop_local_listen (a->app_index, a->wrk_map_index,
				     ll_handle);
      return rv;
    }

  /*
   * Store in local table listener the index of the transport layer
   * listener. We'll need if if local listeners are hit and we need to
   * return global handle
   */
  if (ll_handle != SESSION_INVALID_HANDLE)
    {
      local_session_t *ll;
      stream_session_t *tl;
      ll = application_get_local_listener_w_handle (ll_handle);
      tl = listen_session_get_from_handle (a->handle);
      if (ll->transport_listener_index == ~0)
	ll->transport_listener_index = tl->session_index;
    }
  return rv;
}

static inline int
vnet_unbind_inline (vnet_unbind_args_t * a)
{
  application_t *app;
  int rv;

  if (!(app = application_get_if_valid (a->app_index)))
    {
      SESSION_DBG ("app (%d) not attached", wrk_map_index);
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  if (application_has_local_scope (app))
    {
      if ((rv = application_stop_local_listen (a->app_index,
					       a->wrk_map_index, a->handle)))
	return rv;
    }

  /*
   * Clear the global scope table of the listener
   */
  if (application_has_global_scope (app))
    return application_stop_listen (a->app_index, a->wrk_map_index,
				    a->handle);
  return 0;
}

static int
application_connect (vnet_connect_args_t * a)
{
  app_worker_t *server_wrk, *client_wrk;
  u32 table_index, server_index, li;
  stream_session_t *listener;
  application_t *client, *server;
  local_session_t *ll;
  u8 fib_proto;
  u64 lh;

  if (session_endpoint_is_zero (&a->sep))
    return VNET_API_ERROR_INVALID_VALUE;

  client = application_get (a->app_index);
  session_endpoint_update_for_app (&a->sep_ext, client, 1 /* is_connect */ );
  client_wrk = application_get_worker (client, a->wrk_map_index);

  /*
   * First check the local scope for locally attached destinations.
   * If we have local scope, we pass *all* connects through it since we may
   * have special policy rules even for non-local destinations, think proxy.
   */
  if (application_has_local_scope (client))
    {
      table_index = application_local_session_table (client);
      lh = session_lookup_local_endpoint (table_index, &a->sep);
      if (lh == SESSION_DROP_HANDLE)
	return VNET_API_ERROR_APP_CONNECT_FILTERED;

      if (lh == SESSION_INVALID_HANDLE)
	goto global_scope;

      local_session_parse_handle (lh, &server_index, &li);

      /*
       * Break loop if rule in local table points to connecting app. This
       * can happen if client is a generic proxy. Route connect through
       * global table instead.
       */
      if (server_index != a->app_index)
	{
	  server = application_get (server_index);
	  ll = application_get_local_listen_session (server, li);
	  listener = (stream_session_t *) ll;
	  server_wrk = application_listener_select_worker (listener,
							   1 /* is_local */ );
	  return application_local_session_connect (client_wrk,
						    server_wrk, ll,
						    a->api_context);
	}
    }

  /*
   * If nothing found, check the global scope for locally attached
   * destinations. Make sure first that we're allowed to.
   */

global_scope:
  if (session_endpoint_is_local (&a->sep))
    return VNET_API_ERROR_SESSION_CONNECT;

  if (!application_has_global_scope (client))
    return VNET_API_ERROR_APP_CONNECT_SCOPE;

  fib_proto = session_endpoint_fib_proto (&a->sep);
  table_index = application_session_table (client, fib_proto);
  listener = session_lookup_listener (table_index, &a->sep);
  if (listener)
    {
      server_wrk = application_listener_select_worker (listener,
						       0 /* is_local */ );
      ll = (local_session_t *) listener;
      return application_local_session_connect (client_wrk, server_wrk, ll,
						a->api_context);
    }

  /*
   * Not connecting to a local server, propagate to transport
   */
  if (app_worker_open_session (client_wrk, &a->sep, a->api_context))
    return VNET_API_ERROR_SESSION_CONNECT;
  return 0;
}

/**
 * unformat a vnet URI
 *
 * transport-proto://[hostname]ip46-addr:port
 * eg. 	tcp://ip46-addr:port
 * 	tls://[testtsl.fd.io]ip46-addr:port
 *
 * u8 ip46_address[16];
 * u16  port_in_host_byte_order;
 * stream_session_type_t sst;
 * u8 *fifo_name;
 *
 * if (unformat (input, "%U", unformat_vnet_uri, &ip46_address,
 *              &sst, &port, &fifo_name))
 *  etc...
 *
 */
uword
unformat_vnet_uri (unformat_input_t * input, va_list * args)
{
  session_endpoint_cfg_t *sep = va_arg (*args, session_endpoint_cfg_t *);
  u32 transport_proto = 0, port;

  if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		&transport_proto, unformat_ip4_address, &sep->ip.ip4, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 1;
      return 1;
    }
  else if (unformat (input, "%U://[%s]%U/%d", unformat_transport_proto,
		     &transport_proto, &sep->hostname, unformat_ip4_address,
		     &sep->ip.ip4, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 1;
      return 1;
    }
  else if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		     &transport_proto, unformat_ip6_address, &sep->ip.ip6,
		     &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 0;
      return 1;
    }
  else if (unformat (input, "%U://[%s]%U/%d", unformat_transport_proto,
		     &transport_proto, &sep->hostname, unformat_ip6_address,
		     &sep->ip.ip6, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 0;
      return 1;
    }
  return 0;
}

static u8 *cache_uri;
static session_endpoint_cfg_t *cache_sep;

int
parse_uri (char *uri, session_endpoint_cfg_t * sep)
{
  unformat_input_t _input, *input = &_input;

  if (cache_uri && !strncmp (uri, (char *) cache_uri, vec_len (cache_uri)))
    {
      *sep = *cache_sep;
      return 0;
    }

  /* Make sure */
  uri = (char *) format (0, "%s%c", uri, 0);

  /* Parse uri */
  unformat_init_string (input, uri, strlen (uri));
  if (!unformat (input, "%U", unformat_vnet_uri, sep))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  unformat_free (input);

  vec_free (cache_uri);
  cache_uri = (u8 *) uri;
  if (cache_sep)
    clib_mem_free (cache_sep);
  cache_sep = clib_mem_alloc (sizeof (*sep));
  *cache_sep = *sep;

  return 0;
}

static int
app_validate_namespace (u8 * namespace_id, u64 secret, u32 * app_ns_index)
{
  app_namespace_t *app_ns;
  if (vec_len (namespace_id) == 0)
    {
      /* Use default namespace */
      *app_ns_index = 0;
      return 0;
    }

  *app_ns_index = app_namespace_index_from_id (namespace_id);
  if (*app_ns_index == APP_NAMESPACE_INVALID_INDEX)
    return VNET_API_ERROR_APP_INVALID_NS;
  app_ns = app_namespace_get (*app_ns_index);
  if (!app_ns)
    return VNET_API_ERROR_APP_INVALID_NS;
  if (app_ns->ns_secret != secret)
    return VNET_API_ERROR_APP_WRONG_NS_SECRET;
  return 0;
}

static u8 *
app_name_from_api_index (u32 api_client_index)
{
  vl_api_registration_t *regp;
  regp = vl_api_client_index_to_registration (api_client_index);
  if (regp)
    return format (0, "%s%c", regp->name, 0);

  clib_warning ("api client index %u does not have an api registration!",
		api_client_index);
  return format (0, "unknown%c", 0);
}

/**
 * Attach application to vpp
 *
 * Allocates a vpp app, i.e., a structure that keeps back pointers
 * to external app and a segment manager for shared memory fifo based
 * communication with the external app.
 */
clib_error_t *
vnet_application_attach (vnet_app_attach_args_t * a)
{
  svm_fifo_segment_private_t *fs;
  application_t *app = 0;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  u32 app_ns_index = 0;
  u8 *app_name = 0;
  u64 secret;
  int rv;

  if (a->api_client_index != APP_INVALID_INDEX)
    app = application_lookup (a->api_client_index);
  else if (a->name)
    app = application_lookup_name (a->name);
  else
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				   "api index or name must be provided");

  if (app)
    return clib_error_return_code (0, VNET_API_ERROR_APP_ALREADY_ATTACHED, 0,
				   "app already attached");

  if (a->api_client_index != APP_INVALID_INDEX)
    {
      app_name = app_name_from_api_index (a->api_client_index);
      a->name = app_name;
    }

  secret = a->options[APP_OPTIONS_NAMESPACE_SECRET];
  if ((rv = app_validate_namespace (a->namespace_id, secret, &app_ns_index)))
    return clib_error_return_code (0, rv, 0, "namespace validation: %d", rv);
  a->options[APP_OPTIONS_NAMESPACE] = app_ns_index;

  if ((rv = application_alloc_and_init ((app_init_args_t *) a)))
    return clib_error_return_code (0, rv, 0, "app init: %d", rv);

  app = application_get (a->app_index);
  if ((rv = app_worker_alloc_and_init (app, &app_wrk)))
    return clib_error_return_code (0, rv, 0, "app default wrk init: %d", rv);

  a->app_evt_q = app_wrk->event_queue;
  app_wrk->api_client_index = a->api_client_index;
  sm = segment_manager_get (app_wrk->first_segment_manager);
  fs = segment_manager_get_segment_w_lock (sm, 0);

  if (application_is_proxy (app))
    application_setup_proxy (app);

  ASSERT (vec_len (fs->ssvm.name) <= 128);
  a->segment = &fs->ssvm;
  a->segment_handle = segment_manager_segment_handle (sm, fs);

  segment_manager_segment_reader_unlock (sm);
  vec_free (app_name);
  return 0;
}

/**
 * Detach application from vpp
 */
int
vnet_application_detach (vnet_app_detach_args_t * a)
{
  application_t *app;

  app = application_get_if_valid (a->app_index);
  if (!app)
    {
      clib_warning ("app not attached");
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  app_interface_check_thread_and_barrier (vnet_application_detach, a);
  application_detach_process (app, a->api_client_index);
  return 0;
}

int
vnet_bind_uri (vnet_bind_args_t * a)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  int rv;

  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;
  sep.app_wrk_index = 0;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
  return vnet_bind_inline (a);
}

int
vnet_unbind_uri (vnet_unbind_args_t * a)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  stream_session_t *listener;
  u32 table_index;
  int rv;

  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;

  /* NOTE: only default fib tables supported for uri apis */
  table_index = session_lookup_get_index_for_fib (fib_ip_proto (!sep.is_ip4),
						  0);
  listener = session_lookup_listener (table_index,
				      (session_endpoint_t *) & sep);
  if (!listener)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;
  a->handle = listen_session_get_handle (listener);
  return vnet_unbind_inline (a);
}

clib_error_t *
vnet_connect_uri (vnet_connect_args_t * a)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  int rv;

  /* Parse uri */
  rv = parse_uri (a->uri, &sep);
  if (rv)
    return clib_error_return_code (0, rv, 0, "app init: %d", rv);

  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
  if ((rv = application_connect (a)))
    return clib_error_return_code (0, rv, 0, "connect failed");
  return 0;
}

int
vnet_disconnect_session (vnet_disconnect_args_t * a)
{
  if (session_handle_is_local (a->handle))
    {
      local_session_t *ls;

      /* Disconnect reply came to worker 1 not main thread */
      app_interface_check_thread_and_barrier (vnet_disconnect_session, a);

      if (!(ls = application_get_local_session_from_handle (a->handle)))
	return 0;

      return application_local_session_disconnect (a->app_index, ls);
    }
  else
    {
      app_worker_t *app_wrk;
      stream_session_t *s;

      s = session_get_from_handle_if_valid (a->handle);
      if (!s)
	return VNET_API_ERROR_INVALID_VALUE;
      app_wrk = app_worker_get (s->app_wrk_index);
      if (app_wrk->app_index != a->app_index)
	return VNET_API_ERROR_INVALID_VALUE;

      /* We're peeking into another's thread pool. Make sure */
      ASSERT (s->session_index == session_index_from_handle (a->handle));

      session_close (s);
    }
  return 0;
}

clib_error_t *
vnet_bind (vnet_bind_args_t * a)
{
  int rv;
  if ((rv = vnet_bind_inline (a)))
    return clib_error_return_code (0, rv, 0, "bind failed: %d", rv);
  return 0;
}

clib_error_t *
vnet_unbind (vnet_unbind_args_t * a)
{
  int rv;
  if ((rv = vnet_unbind_inline (a)))
    return clib_error_return_code (0, rv, 0, "unbind failed: %d", rv);
  return 0;
}

clib_error_t *
vnet_connect (vnet_connect_args_t * a)
{
  int rv;

  if ((rv = application_connect (a)))
    return clib_error_return_code (0, rv, 0, "connect failed: %d", rv);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
