/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <http_static/http_static.h>
#include <vpp/app/version.h>

hss_url_handler_rc_t
handle_get_version (hss_url_handler_args_t *args)
{
  u8 *s = 0;

  s = format (s, "{\"vpp_details\": {");
  s = format (s, "   \"version\": \"%s\",", VPP_BUILD_VER);
  s = format (s, "   \"build_date\": \"%s\"}}\r\n", VPP_BUILD_DATE);

  args->data = s;
  args->data_len = vec_len (s);
  args->free_vec_data = 1;
  return HSS_URL_HANDLER_OK;
}

void
trim_path_from_request (u8 *s, char *path)
{
  u8 *cp;
  int trim_length = strlen (path) + 1 /* remove '?' */;

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
	  vec_set_len (s, cp - s);
	  break;
	}
      cp++;
    }
}

hss_url_handler_rc_t
handle_get_interface_stats (hss_url_handler_args_t *args)
{
  u8 *s = 0, *stats = 0;
  uword *p;
  u32 *sw_if_indices = 0;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  char *q = "\"";
  int i;
  int need_comma = 0;
  u8 *format_vnet_sw_interface_cntrs (u8 * s, vnet_interface_main_t * im,
				      vnet_sw_interface_t * si, int json);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;

  /* Get stats for a single interface via http POST */
  if (args->reqtype == HTTP_REQ_POST)
    {
      trim_path_from_request (args->request, "interface_stats.json");

      /* Find the sw_if_index */
      p = hash_get (im->hw_interface_by_name, args->request);
      if (!p)
	{
	  s = format (s, "{\"interface_stats\": {[\n");
	  s = format (s, "   \"name\": \"%s\",", args->request);
	  s = format (s, "   \"error\": \"%s\"", "UnknownInterface");
	  s = format (s, "]}\n");
	  goto out;
	}

      vec_add1 (sw_if_indices, p[0]);
    }
  else /* default, HTTP_BUILTIN_METHOD_GET */
    {
      pool_foreach (hi, im->hw_interfaces)
	{
	  vec_add1 (sw_if_indices, hi->sw_if_index);
	}
    }

  s = format (s, "{%sinterface_stats%s: [\n", q, q);

  for (i = 0; i < vec_len (sw_if_indices); i++)
    {
      si = vnet_get_sw_interface (vnm, sw_if_indices[i]);
      if (need_comma)
	s = format (s, ",\n");

      need_comma = 1;

      s = format (s, "{%sname%s: %s%U%s, ", q, q, q,
		  format_vnet_sw_if_index_name, vnm, sw_if_indices[i], q);

      stats = format_vnet_sw_interface_cntrs (stats, &vnm->interface_main, si,
					      1 /* want json */);
      if (vec_len (stats))
	s = format (s, "%v}", stats);
      else
	s = format (s, "%snone%s: %strue%s}", q, q, q, q);
      vec_reset_length (stats);
    }

  s = format (s, "]}\n");

out:
  args->data = s;
  args->data_len = vec_len (s);
  args->free_vec_data = 1;
  vec_free (sw_if_indices);
  vec_free (stats);
  return HSS_URL_HANDLER_OK;
}

hss_url_handler_rc_t
handle_get_interface_list (hss_url_handler_args_t *args)
{
  u8 *s = 0;
  int i;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  u32 *hw_if_indices = 0;
  int need_comma = 0;

  /* Construct vector of active hw_if_indexes ... */
  pool_foreach (hi, im->hw_interfaces)
    {
      /* No point in mentioning "local0"... */
      if (hi - im->hw_interfaces)
	vec_add1 (hw_if_indices, hi - im->hw_interfaces);
    }

  /* Build answer */
  s = format (s, "{\"interface_list\": [\n");
  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      if (need_comma)
	s = format (s, ",\n");
      hi = pool_elt_at_index (im->hw_interfaces, hw_if_indices[i]);
      s = format (s, "\"%v\"", hi->name);
      need_comma = 1;
    }
  s = format (s, "]}\n");
  vec_free (hw_if_indices);

  args->data = s;
  args->data_len = vec_len (s);
  args->free_vec_data = 1;
  return HSS_URL_HANDLER_OK;
}

void
hss_builtinurl_json_handlers_init (void)
{
  hss_register_url_handler (handle_get_version, "version.json", HTTP_REQ_GET);
  hss_register_url_handler (handle_get_interface_list, "interface_list.json",
			    HTTP_REQ_GET);
  hss_register_url_handler (handle_get_interface_stats, "interface_stats.json",
			    HTTP_REQ_GET);
  hss_register_url_handler (handle_get_interface_stats, "interface_stats.json",
			    HTTP_REQ_POST);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
