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
#include <vlib/vlib.h>
#include <vlibapi/api_types.h>
#include <vppinfra/cJSON.h>

/* VPP API client includes */
#include <vpp-api/client/vppapiclient.h>

#include "vat2.h"
#include <limits.h>

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
  printf("Received something async: %d\n", result_msg_id);
}

vat2_main_t vat2_main;

/*
 * Temporary API
 */

void setup_message_id_table(uword *);
int vat2_load_plugins (char *path, char *filter, int *loaded);

static int
register_function (vat2_main_t *vam)
{
  int loaded;

  //setup_message_id_table(vam->function_by_name);
  vat2_find_plugin_path();
  printf("Plugin Path %s\n", vat2_plugin_path);
  int rv = vat2_load_plugins(vat2_plugin_path, 0, &loaded);
  printf("Loaded %u plugins\n", loaded);
  return rv;
}

void
vat2_register_function(char *name, cJSON (*f)(cJSON *))
{
  vat2_main_t *vam = &vat2_main;
  hash_set_mem(vam->function_by_name, name, f);
}


int main (int argc, char **argv)
{
  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);

  vat2_main_t *vam = &vat2_main;

  vam->function_by_name = hash_create_string (0, sizeof (uword));
  int res = register_function(vam);
  if (res < 0) {
    fprintf(stderr, "%s: loading plugins failed\n", argv[0]);
    exit(-1);
  }

  if (argc < 2) {
    fprintf(stderr, "%s: required command missing\n", argv[0]);
    exit(-1);
  }
  /* Command line arguments */
  uword *p = hash_get_mem (vam->function_by_name, argv[1]);
  if (p == 0) {
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
      exit(-1);
  }

  cJSON *o = 0;

  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(0, &fds);
  struct timeval timeout = { 0 };
  select(1, &fds, 0, 0, &timeout);

  if (FD_ISSET(0, &fds)) {
    size_t bufsize = 1024;
    char *buf = malloc(bufsize);
    size_t n_read = 0;
    size_t n;

    while ((n = fread(buf, 1, bufsize, stdin))) {
      n_read += n;
      if (n == bufsize)
        buf = realloc(buf, bufsize);
    }
    if (n_read) {
      o = cJSON_Parse(buf);
      free(buf);
      if (!o) {
        fprintf(stderr, "Failed parsing JSON input: %s\n", cJSON_GetErrorPtr());
        exit(-1);
      }
    }
  }

  if (vac_connect("vat2", 0, 0, 1024)) {
    fprintf(stderr, "Failed connecting to VPP\n");
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
