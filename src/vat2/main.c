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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <getopt.h>
#include <vlib/vlib.h>
#include <vlibapi/api_types.h>
#include <vppinfra/hash.h>
#include <vppinfra/cJSON.h>

/* VPP API client includes */
#include <vpp-api/client/vppapiclient.h>

#include <limits.h>
#include "vat2.h"

uword *function_by_name;
bool debug = false;

char *vat2_plugin_path;
static void
vat2_find_plugin_path ()
{
  char *p, path[PATH_MAX];
  int rv;
  u8 *s;

  /* find executable path */
  if ((rv = readlink ("/proc/self/exe", path, PATH_MAX - 1)) == -1)
    return;

  /* readlink doesn't provide null termination */
  path[rv] = 0;

  /* strip filename */
  if ((p = strrchr (path, '/')) == 0)
    return;
  *p = 0;

  /* strip bin/ */
  if ((p = strrchr (path, '/')) == 0)
    return;
  *p = 0;

  s = format (0, "%s/lib/" CLIB_TARGET_TRIPLET "/vat2_plugins:"
              "%s/lib/vat2_plugins", path, path);
  vec_add1 (s, 0);
  vat2_plugin_path = (char *) s;
}

void
vac_callback (unsigned char *data, int len)
{
  u16 result_msg_id = ntohs(*((u16 *)data));
  DBG("Received something async: %d\n", result_msg_id);
}

int vat2_load_plugins (char *path, char *filter, int *loaded);

static int
register_function (void)
{
  int loaded;

  vat2_find_plugin_path();
  DBG("Plugin Path %s\n", vat2_plugin_path);
  int rv = vat2_load_plugins(vat2_plugin_path, 0, &loaded);
  DBG("Loaded %u plugins\n", loaded);
  return rv;
}

struct apifuncs_s
{
  cJSON (*f) (cJSON *);
  cJSON (*tojson) (void *);
  u32 crc;
};

struct apifuncs_s *apifuncs = 0;

void
vat2_register_function (char *name, cJSON (*f) (cJSON *),
			cJSON (*tojson) (void *), u32 crc)
{
  struct apifuncs_s funcs = { .f = f, .tojson = tojson, .crc = crc };
  vec_add1 (apifuncs, funcs);
  hash_set_mem (function_by_name, name, vec_len (apifuncs) - 1);
}

static int
vat2_exec_command_by_name (char *msgname, cJSON *o)
{

  cJSON *crc_obj = cJSON_GetObjectItem (o, "_crc");
  if (!crc_obj)
    {
      fprintf (stderr, "Missing '_crc' element!\n");
      return -1;
    }
  char *crc_str = cJSON_GetStringValue (crc_obj);
  u32 crc = (u32) strtol (crc_str, NULL, 16);

  uword *p = hash_get_mem (function_by_name, msgname);
  if (!p)
    {
      fprintf (stderr, "No such command %s\n", msgname);
      return -1;
    }
  if (crc != apifuncs[p[0]].crc)
    {
      fprintf (stderr, "API CRC does not match: %s!\n", msgname);
    }

  cJSON *(*fp) (cJSON *);
  fp = (void *) apifuncs[p[0]].f;
  cJSON *r = (*fp) (o);

  if (r)
    {
      char *output = cJSON_Print (r);
      cJSON_Delete (r);
      printf ("%s\n", output);
      free (output);
    }
  else
    {
      fprintf (stderr, "Call failed: %s\n", msgname);
      return -1;
    }
  return 0;
}

static int
vat2_exec_command (cJSON *o)
{

  cJSON *msg_id_obj = cJSON_GetObjectItem (o, "_msgname");
  if (!msg_id_obj)
    {
      fprintf (stderr, "Missing '_msgname' element!\n");
      return -1;
    }

  char *name = cJSON_GetStringValue (msg_id_obj);

  return vat2_exec_command_by_name (name, o);
}

static void
print_template (char *msgname)
{
  uword *p = hash_get_mem (function_by_name, msgname);
  if (!p)
    goto error;

  cJSON *(*fp) (void *);
  fp = (void *) apifuncs[p[0]].tojson;
  if (!fp)
    goto error;

  void *scratch = malloc (2048);
  if (!scratch)
    goto error;

  memset (scratch, 0, 2048);
  cJSON *t = fp (scratch);
  if (!t)
    goto error;
  free (scratch);
  char *output = cJSON_Print (t);
  if (!output)
    goto error;

  cJSON_Delete (t);
  printf ("%s\n", output);
  free (output);

  return;

error:
  fprintf (stderr, "error printing template for: %s\n", msgname);
}

static void
dump_apis (void)
{
  char *name;
  u32 *i;
  hash_foreach_mem (name, i, function_by_name, ({ printf ("%s\n", name); }));
}

static void
print_help (void)
{
  char *help_string =
    "Usage: vat2 [OPTION] <message-name> <JSON object>\n"
    "Send API message to VPP and print reply\n"
    "\n"
    "-d, --debug       Print additional information\n"
    "-p, --prefix      Specify shared memory prefix to connect to a given VPP "
    "instance\n"
    "-f, --file        File containing a JSON object with the arguments for "
    "the message to send\n"
    "--dump-apis       List all APIs available in VAT2 (might not reflect "
    "running VPP)\n"
    "-t, --template    Print a template JSON object for given API message\n"
    "\n";
  printf ("%s", help_string);
}

int main (int argc, char **argv)
{
  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);
  char *filename = 0, *prefix = 0;
  int index;
  int c;
  opterr = 0;
  cJSON *o = 0;
  int option_index = 0;
  bool dump_api = false;
  bool template = false;
  char *msgname = 0;
  static int debug_flag;
  static struct option long_options[] = {
    { "debug", no_argument, &debug_flag, 1 },
    { "prefix", optional_argument, 0, 'p' },
    { "file", required_argument, 0, 'f' },
    { "dump-apis", no_argument, 0, 0 },
    { "template", no_argument, 0, 't' },
    { 0, 0, 0, 0 }
  };

  while ((c = getopt_long (argc, argv, "hdp:f:", long_options,
			   &option_index)) != -1)
    {
      switch (c)
	{
	case 0:
	  if (option_index == 3)
	    dump_api = true;
	  break;
	case 'd':
	  debug = true;
	  break;
	case 't':
	  template = true;
	  break;
	case 'p':
	  prefix = optarg;
	  break;
	case 'f':
	  filename = optarg;
	  break;
	case '?':
	  print_help ();
	  return 1;
	default:
	  abort ();
	}
    }
  debug = debug_flag == 1 ? true : false;
  DBG ("debug = %d, filename = %s shared memory prefix: %s\n", debug, filename,
       prefix);

  for (index = optind; index < argc; index++)
    DBG ("Non-option argument %s\n", argv[index]);

  index = optind;

  if (argc > index + 2)
    {
      fprintf (stderr, "%s: Too many arguments\n", argv[0]);
      exit (-1);
    }

  /* Load plugins */
  function_by_name = hash_create_string (0, sizeof (uword));
  int res = register_function();
  if (res < 0) {
    fprintf(stderr, "%s: loading plugins failed\n", argv[0]);
    exit(-1);
  }

  if (template)
    {
      print_template (argv[index]);
      exit (0);
    }

  if (dump_api)
    {
      dump_apis ();
      exit (0);
    }

  /* Read message arguments from command line */
  if (argc >= (index + 1))
    {
      msgname = argv[index];
    }
  if (argc == (index + 2)) {
    o = cJSON_Parse(argv[index+1]);
    if (!o) {
      fprintf(stderr, "%s: Failed parsing JSON input: %s\n", argv[0], cJSON_GetErrorPtr());
      exit(-1);
    }
  }

  if (!msgname && !filename)
    {
      print_help ();
      exit (-1);
    }

  /* Read message from file */
  if (filename) {
      if (argc > index)
	{
	  fprintf (stderr, "%s: Superfluous arguments when filename given\n",
		   argv[0]);
	  exit (-1);
	}

    FILE *f = fopen(filename, "r");
    size_t chunksize, bufsize;
    size_t n_read = 0;
    size_t n;

    if (!f) {
      fprintf(stderr, "%s: can't open file: %s\n", argv[0], filename);
      exit(-1);
    }

    chunksize = bufsize = 1024;
    char *buf = malloc(bufsize);
    while ((n = fread (buf + n_read, 1, chunksize, f)))
      {
	n_read += n;
	if (n == chunksize)
	  {
	    bufsize += chunksize;
	    buf = realloc (buf, bufsize);
	  }
      }
    fclose(f);
    if (n_read) {
      o = cJSON_Parse(buf);
      if (!o) {
        fprintf(stderr, "%s: Failed parsing JSON input: %s\n", argv[0], cJSON_GetErrorPtr());
        exit(-1);
      }
    }
    free (buf);
  }

  if (!o)
    {
      fprintf (stderr, "%s: Failed parsing JSON input\n", argv[0]);
      exit (-1);
    }

  if (vac_connect ("vat2", prefix, 0, 1024))
    {
      fprintf (stderr, "Failed connecting to VPP\n");
      exit (-1);
    }

  if (msgname)
    {
      vat2_exec_command_by_name (msgname, o);
    }
  else
    {
      if (cJSON_IsArray (o))
	{
	  size_t size = cJSON_GetArraySize (o);
	  for (int i = 0; i < size; i++)
	    vat2_exec_command (cJSON_GetArrayItem (o, i));
	}
    }
  cJSON_Delete (o);
  vac_disconnect();
  exit (0);

}
