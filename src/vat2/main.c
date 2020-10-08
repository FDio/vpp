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
#include <stdbool.h>
#include <ctype.h>
#include <vlib/vlib.h>
#include <vlibapi/api_types.h>
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

void
vat2_register_function(char *name, cJSON (*f)(cJSON *))
{
  hash_set_mem(function_by_name, name, f);
}

int main (int argc, char **argv)
{
  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);
  char *filename = 0;
  int index;
  int c;
  opterr = 0;
  cJSON *o = 0;
  uword *p = 0;

  while ((c = getopt (argc, argv, "df:")) != -1) {
    switch (c) {
      case 'd':
        debug = true;
        break;
      case 'f':
        filename = optarg;
        break;
      case '?':
        if (optopt == 'f')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort ();
    }
  }

  DBG("debug = %d, filename = %s\n", debug, filename);

  for (index = optind; index < argc; index++)
    DBG ("Non-option argument %s\n", argv[index]);

  index = optind;

  /* Load plugins */
  function_by_name = hash_create_string (0, sizeof (uword));
  int res = register_function();
  if (res < 0) {
    fprintf(stderr, "%s: loading plugins failed\n", argv[0]);
    exit(-1);
  }

  if (argc > index + 2) {
    fprintf(stderr, "%s: Too many arguments\n", argv[0]);
    exit(-1);
  }

  /* Read JSON from stdin, command line or file */
  if (argc >= (index + 1)) {
    p = hash_get_mem (function_by_name, argv[index]);
    if (p == 0) {
      fprintf(stderr, "%s: Unknown command: %s\n", argv[0], argv[index]);
      exit(-1);
    }
  }

  if (argc == (index + 2)) {
    o = cJSON_Parse(argv[index+1]);
    if (!o) {
      fprintf(stderr, "%s: Failed parsing JSON input: %s\n", argv[0], cJSON_GetErrorPtr());
      exit(-1);
    }
  }

  if (filename) {
    if (argc > index + 1) {
      fprintf(stderr, "%s: Superfluous arguments when filename given\n", argv[0]);
      exit(-1);
    }

    FILE *f = fopen(filename, "r");
    size_t bufsize = 1024;
    size_t n_read = 0;
    size_t n;

    if (!f) {
      fprintf(stderr, "%s: can't open file: %s\n", argv[0], filename);
      exit(-1);
    }
    char *buf = malloc(bufsize);
    while ((n = fread(buf, 1, bufsize, f))) {
      n_read += n;
      if (n == bufsize)
        buf = realloc(buf, bufsize);
    }
    fclose(f);
    if (n_read) {
      o = cJSON_Parse(buf);
      free(buf);
      if (!o) {
        fprintf(stderr, "%s: Failed parsing JSON input: %s\n", argv[0], cJSON_GetErrorPtr());
        exit(-1);
      }
    }
  }

  if (!o) {
    fprintf(stderr, "%s: Failed parsing JSON input\n", argv[0]);
    exit(-1);
  }

  if (vac_connect("vat2", 0, 0, 1024)) {
    fprintf(stderr, "Failed connecting to VPP\n");
    exit(-1);
  }
  if (!p) {
    fprintf(stderr, "No such command\n");
    exit(-1);
  }

  cJSON * (*fp) (cJSON *);
  fp = (void *) p[0];
  cJSON *r = (*fp) (o);

  if (o)
    cJSON_Delete(o);

  if (r) {
    char *output = cJSON_Print(r);
    cJSON_Delete(r);
    printf("%s\n", output);
    free(output);
  } else {
    fprintf(stderr, "Call failed\n");
    exit(-1);
  }

  vac_disconnect();
  exit (0);

}
