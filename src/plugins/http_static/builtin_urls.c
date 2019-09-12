/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <http_static/http_static.h>
#include <vpp/app/version.h>

int handle_get_version (u8 *request, http_session_t *hs)
{
  u8 *s = 0;

  /* Build some json bullshit */
  s = format (s, "{\"vpp_details\": {");
  s = format (s, "   \"version\": \"%s\",",
              VPP_BUILD_VER);
  s = format (s, "   \"build_date\": \"%s\"}}\r\n",
              VPP_BUILD_DATE);

  hs->data = s;
  hs->data_offset = 0;
  hs->cache_pool_index = ~0;
  hs->free_data = 1;
  return 0;
}

void http_static_builtin_url_init (void)
{
    http_static_server_register_builtin_handler
        (handle_get_version, "version.json", 0 /* GET */);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
