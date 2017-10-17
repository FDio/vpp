/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/session/session_table.h>

#ifndef SRC_VNET_SESSION_APPLICATION_NAMESPACE_H_
#define SRC_VNET_SESSION_APPLICATION_NAMESPACE_H_

typedef struct _app_namespace
{
  /**
   * Local sw_if_index that supports transport connections for this namespace
   */
  u32 sw_if_index;

  /**
   * Network namespace (e.g., fib_index associated to the sw_if_index)
   * wherein connections are to be established. Since v4 and v6 fibs are
   * separate, we actually need to keep pointers to both.
   */
  u32 ip4_fib_index;
  u32 ip6_fib_index;

  /**
   * Local session table associated to ns
   */
  u32 local_table_index;

  /**
   * Secret apps need to provide to authorize attachment to the namespace
   */
  u64 ns_secret;

  /**
   * Application namespace id
   */
  u8 *ns_id;
} app_namespace_t;

typedef struct _vnet_app_namespace_add_del_args
{
  u8 *ns_id;
  u64 secret;
  u32 sw_if_index;
  u32 ip4_fib_id;
  u32 ip6_fib_id;
  u8 is_add;
} vnet_app_namespace_add_del_args_t;

#define APP_NAMESPACE_INVALID_INDEX ((u32)~0)

app_namespace_t *app_namespace_alloc (u8 * ns_id);
app_namespace_t *app_namespace_get (u32 index);
app_namespace_t *app_namespace_get_from_id (const u8 * ns_id);
u32 app_namespace_index (app_namespace_t * app_ns);
const u8 *app_namespace_id (app_namespace_t * app_ns);
const u8 *app_namespace_id_from_index (u32 index);
u32 app_namespace_index_from_id (const u8 * ns_id);
void app_namespaces_init (void);
clib_error_t *vnet_app_namespace_add_del (vnet_app_namespace_add_del_args_t *
					  a);
u32 app_namespace_get_fib_index (app_namespace_t * app_ns, u8 fib_proto);
session_table_t *app_namespace_get_local_table (app_namespace_t * app_ns);

always_inline app_namespace_t *
app_namespace_get_default (void)
{
  return app_namespace_get (0);
}

#endif /* SRC_VNET_SESSION_APPLICATION_NAMESPACE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
