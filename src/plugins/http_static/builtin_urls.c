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

int
handle_get_version (u8 * request, http_session_t * hs)
{
  u8 *s = 0;

  /* Build some json bullshit */
  s = format (s, "{\"vpp_details\": {");
  s = format (s, "   \"version\": \"%s\",", VPP_BUILD_VER);
  s = format (s, "   \"build_date\": \"%s\"}}\r\n", VPP_BUILD_DATE);

  hs->data = s;
  hs->data_offset = 0;
  hs->cache_pool_index = ~0;
  hs->free_data = 1;
  return 0;
}

void
trim_path_from_request (u8 * s, char *path)
{
  u8 *cp;
  int trim_length = strlen (path) + 1 /* remove '?' */ ;

  /* Get rid of the path and question-mark */
  vec_delete (s, trim_length, 0);

  /* Tail trim irrelevant browser info */
  cp = s;
  while ((cp - s) < vec_len (s))
    {
      if (*cp == ' ')
	{
	  /*
	   * Makes request a vector which happens to look
	   * like a c-string.
	   */
	  *cp = 0;
	  _vec_len (s) = cp - s;
	  break;
	}
      cp++;
    }
}

int
handle_get_interface_stats (u8 * request, http_session_t * hs)
{
  u8 *s = 0, *stats = 0;
  u32 sw_if_index;
  uword *p;
  vnet_sw_interface_t *si;
  u8 *format_vnet_sw_interface_cntrs (u8 * s, vnet_interface_main_t * im,
				      vnet_sw_interface_t * si, int json);

  vnet_main_t *vnm = vnet_get_main ();

  trim_path_from_request (request, "interface_stats.json");

  /* get data */

  p = hash_get (vnm->interface_main.hw_interface_by_name, request);
  if (!p)
    {
      clib_warning ("Couldn't find interface '%v'", request);

      s = format (s, "{\"interface_stats\": {");
      s = format (s, "   \"name\": \"%s\",", request);
      s = format (s, "   \"stats\": \"%s\"", "ERRORUnknownInterface");
      s = format (s, "}}\r\n");
      goto out;
    }

  sw_if_index = p[0];
  si = vnet_get_sw_interface (vnm, sw_if_index);

  stats = format_vnet_sw_interface_cntrs (stats, &vnm->interface_main, si,
					  1 /* want json */ );
  /* Build answer */
  s = format (s, "{\"interface_stats\": {");
  s = format (s, "\"name\": \"%s\",\n", request);
  s = format (s, "%s", stats);
  s = format (s, "}}\n");
  vec_free (stats);

out:
  hs->data = s;
  hs->data_offset = 0;
  hs->cache_pool_index = ~0;
  hs->free_data = 1;
  return 0;
}

void
http_static_builtin_url_init (void)
{
  http_static_server_register_builtin_handler
    (handle_get_version, "version.json", 0 /* GET */ );
  http_static_server_register_builtin_handler
    (handle_get_interface_stats, "interface_stats.json", 1 /* POST */ );
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
