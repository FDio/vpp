/*
 * parse_util.c - halfhearted json parser
 *
 * Copyright (c) 2018 Cisco Systems and/or its affiliates
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

#include <perfmon/perfmon.h>
#include <vppinfra/unix.h>

typedef enum
{
  STATE_START,
  STATE_READ_NAME,
  STATE_READ_VALUE,
} parse_state_t;

static u8 *
downcase (u8 * s)
{
  u8 *rv = 0;
  u8 c;
  int i;

  for (i = 0; i < vec_len (s); i++)
    {
      c = s[i];
      if (c >= 'A' && c <= 'Z')
	c = c + ('a' - 'A');
      vec_add1 (rv, c);
    }
  return (rv);
}

uword *
perfmon_parse_table (perfmon_main_t *pm, char *path, char *table_name)
{
  u8 *cp;
  u8 *event_name;
  int state = STATE_START;
  uword *ht;
  name_value_pair_t *nvp = 0;
  name_value_pair_t **nvps = 0;
  u8 *v;
  int i;
  u8 *json_filename;
  clib_error_t *error;
  
  /* Create the name/value hash table in any case... */
  ht = hash_create_string (0, sizeof (uword));

  json_filename = format (0, "%s/%s%c", path, table_name, 0);

  vlib_log_debug (pm->log_class, "Try to read perfmon events from %s",
                  json_filename);

  error = unix_proc_file_contents ((char *)json_filename, &cp);

  if (error)
    {
      vlib_log_err (pm->log_class, "Failed, return empty event table");
      vec_free (json_filename);
      clib_error_report (error);
      return ht;
    }
  vlib_log_debug (pm->log_class, "Read OK, parse the event table...");
  vec_free (json_filename);

again:
  while (*cp)
    {
      switch (state)
	{
	case STATE_START:
	  while (*cp && *cp != '{' && *cp != '}' && *cp != ',')
	    cp++;
	  if (*cp == 0)
	    goto done;

	  /* Look for a new event */
	  if (*cp == '{')
	    {
	      if (*cp == 0)
		{
		error:
		  clib_warning ("parse fail");
		  hash_free (ht);
		  return 0;
		}
	      cp++;
	      state = STATE_READ_NAME;
	      goto again;
	    }
	  else if (*cp == '}')	/* end of event */
	    {
	      /* Look for the "EventName" nvp */
	      for (i = 0; i < vec_len (nvps); i++)
		{
		  nvp = nvps[i];
		  if (!strncmp ((char *) nvp->name, "EventName", 9))
		    {
		      event_name = nvp->value;
		      goto found;
		    }
		}
	      /* no name? */
	      for (i = 0; i < vec_len (nvps); i++)
		{
		  vec_free (nvps[i]->name);
		  vec_free (nvps[i]->value);
		}
	      vec_free (nvps);
	      cp++;
	      goto again;

	    found:
	      event_name = downcase (event_name);
	      hash_set_mem (ht, event_name, nvps);
	      nvp = 0;
	      nvps = 0;
	      cp++;
	      goto again;
	    }
	  else if (*cp == ',')	/* punctuation */
	    {
	      cp++;
	      goto again;
	    }

	case STATE_READ_NAME:
	  vec_validate (nvp, 0);
	  v = 0;
	  while (*cp && *cp != '"')
	    cp++;

	  if (*cp == 0)
	    {
	      vec_free (nvp);
	      goto error;
	    }

	  cp++;
	  while (*cp && *cp != '"')
	    {
	      vec_add1 (v, *cp);
	      cp++;
	    }
	  if (*cp == 0)
	    {
	      vec_free (v);
	      goto error;
	    }
	  cp++;
	  vec_add1 (v, 0);
	  nvp->name = v;
	  state = STATE_READ_VALUE;
	  goto again;

	case STATE_READ_VALUE:
	  while (*cp && *cp != ':')
	    cp++;
	  if (*cp == 0)
	    {
	      vec_free (nvp->name);
	      goto error;
	    }
	  while (*cp && *cp != '"')
	    cp++;
	  if (*cp == 0)
	    {
	      vec_free (nvp->name);
	      goto error;
	    }
	  else
	    cp++;
	  v = 0;
	  while (*cp && *cp != '"')
	    {
	      vec_add1 (v, *cp);
	      cp++;
	    }
	  if (*cp == 0)
	    {
	      vec_free (nvp->name);
	      vec_free (v);
	      goto error;
	    }
	  vec_add1 (v, 0);
	  nvp->value = v;
	  vec_add1 (nvps, nvp);
	  while (*cp && *cp != ',' && *cp != '}')
	    cp++;
	  if (*cp == 0)
	    {
	      vec_free (nvp->name);
	      vec_free (nvp->value);
	      goto error;
	    }
	  else if (*cp == '}')
	    state = STATE_START;
	  else
	    {
	      cp++;
	      state = STATE_READ_NAME;
	    }
	  nvp = 0;
	  goto again;
	}
    }

done:
  return (ht);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
