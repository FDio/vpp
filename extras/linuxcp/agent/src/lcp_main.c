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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>

#include <json-c/json.h>

#include <lcp_log.h>
#include <lcp_nl.h>
#include <lcp_itf_pair.h>
#include <lcp_router.h>
#include <vc_conn.h>
#include <vc_itf.h>
#include <vc_keepalive.h>

static char *
read_file (const char *file)
{
  FILE *f = fopen (file, "r");
  size_t len;

  if (NULL != f)
    {
      char *str = NULL;

      fseek (f, 0, SEEK_END);
      len = ftell (f);
      rewind (f);

      str = malloc (len);

      if (str)
	{
	  if (fread (str, 1, len, f) != len)
	    {
	      LCP_ERROR ("Couldn't read while file");
	      free (str);
	      str = 0;
	    }
	}

      fclose (f);
      return (str);
    }
  return (NULL);
}

static bool
lcp_json_parse_pair (json_object * jpair)
{
  int n;

  n = json_object_array_length (jpair);

  LCP_DBG ("n: %d", n);

  if (n == 2)
    return (0 == lcp_itf_pair_create
	    (json_object_get_string
	     (json_object_array_get_idx (jpair, 0)),
	     json_object_get_string
	     (json_object_array_get_idx (jpair, 1)), NULL));
  else if (n == 3)
    return (0 == lcp_itf_pair_create
	    (json_object_get_string
	     (json_object_array_get_idx (jpair, 0)),
	     json_object_get_string
	     (json_object_array_get_idx (jpair, 1)),
	     json_object_get_string (json_object_array_get_idx (jpair, 2))));

  LCP_ERROR ("json: invalid pair: %s", json_object_get_string (jpair));
  return (false);
}

static bool
lcp_json_parse_pairs (json_object * jobj)
{
  json_object *jpair;
  int ii, n_pairs;

  n_pairs = json_object_array_length (jobj);

  LCP_DBG ("n_pairs: %d", n_pairs);

  for (ii = 0; ii < n_pairs; ii++)
    {
      jpair = json_object_array_get_idx (jobj, ii);

      LCP_DBG ("value[%d]: %s", ii, json_object_get_string (jpair));

      if (!lcp_json_parse_pair (jpair))
	return (false);
    }

  return (true);
}

static bool
lcp_json_parse_top (json_object * jobj)
{
  enum json_type type;

  json_object_object_foreach (jobj, key, val)
  {
    type = json_object_get_type (val);

    LCP_DBG ("key: %s", key);

    if (0 == strncmp (key, "pairs", strlen ("pairs")))
      {
	switch (type)
	  {
	  case json_type_array:
	    return (lcp_json_parse_pairs (val));
	  default:
	    LCP_ERROR ("json: \"pairs\" key should be an array");
	    return (false);
	    break;
	  }
      }
  }

  LCP_ERROR ("json data not found");
  return (false);
}

int
main (int argc, char **argv)
{
  int fd_vapi, fd_nl, n_fds, opt;
  const char *cfg_file;
  char *str;
  fd_set fds;

  cfg_file = str = NULL;

  while ((opt = getopt (argc, argv, "c:")) != -1)
    {
      switch (opt)
	{
	case 'c':
	  cfg_file = optarg;
	  break;
	default:
	  LCP_ERROR ("Usage: %s [-c <CONFIG-FILE>]\n", argv[0]);
	  exit (EXIT_FAILURE);
	}
    }

  LCP_DBG ("Connect");
  fd_vapi = vc_conn_connect ();
  LCP_INFO ("Connected");

  if (cfg_file)
    {
      str = read_file (cfg_file);

      if (!str)
	{
	  LCP_ERROR ("Could not open: %s", cfg_file);
	  exit (EXIT_FAILURE);
	}
    }

  /* init interface module */
  vc_itf_init ();
  vc_itf_populate (vc_conn_ctx ());
  vc_itf_reg_events (vc_conn_ctx (), lcp_itf_pair_state_change, NULL);

  /* init the routing module */
  lcp_router_init ();

  /* parse the config file, if there is one, and install
   * the pairs contained therein */
  if (str)
    {
      json_object *jobj = json_tokener_parse (str);

      if (NULL == jobj)
	{
	  LCP_ERROR ("Could parse json: %s", cfg_file);
	  exit (EXIT_FAILURE);
	}

      if (!lcp_json_parse_top (jobj))
	{
	  LCP_ERROR ("Json file did not contain valid data");
	  exit (EXIT_FAILURE);
	}

      free (str);
    }

  fd_nl = lcp_nl_connect ();
  n_fds = (fd_vapi > fd_nl ? fd_vapi : fd_nl);

  while (vc_conn_up ())
    {
      struct timeval tv = {
	.tv_sec = 1,
	.tv_usec = 0,
      };

      FD_ZERO (&fds);
      FD_SET (fd_vapi, &fds);
      FD_SET (fd_nl, &fds);

      int retval = select (n_fds + 1, &fds, NULL, NULL, &tv);

      if (retval == -1 && errno == EINTR)
	continue;

      if (retval == -1)
	{
	  exit (EXIT_FAILURE);
	}
      else if (FD_ISSET (fd_nl, &fds))
	{
	  lcp_nl_read ();
	}
      else if (FD_ISSET (fd_vapi, &fds))
	vc_conn_dispatch (fd_vapi);
      /* else */
      /*   LCP_DBG ("timeout"); */
    }

  perror ("VPP Keepalive failure");
  return (EXIT_FAILURE);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
