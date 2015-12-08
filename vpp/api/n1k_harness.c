/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <dlfcn.h>
#include <vppinfra/format.h>

void vlib_cli_output (void * vm, char * fmt, ...)
{ clib_warning ("%s", fmt); }

/* 
 * build system finesse hack 
 * since we can't build everything in one build system, this
 * hack exists to make sure that the invoked program runs against
 * the right libraries.
 */

int main (int argc, char ** argv)
{
  void *handle, *main_handle;
  int (*fp)(int argc, char **argv);
  int rv;
  
  /* n1k_harness <plugin-name> <plugin args> */

  if (argc < 2) {
      fformat (stderr, "usage: %s <plugin-name> [<plugin-args>...]\n",
               argv[0]);
      exit (1);
  }

  handle = dlopen (argv[1], RTLD_LAZY);

  /* 
   * Note: this can happen if the plugin has an undefined symbol reference,
   * so print a warning. Otherwise, the poor slob won't know what happened.
   * Ask me how I know that...
   */
  if (handle == 0)
    {
      clib_warning ("%s", dlerror());
      exit(1);
    }
  
  main_handle = dlsym (handle, "plugin_main");
  if (main_handle == 0) {
      clib_warning ("plugin_main(int argc, char **argv) missing...\n");
      exit(1);
  }

  fp = main_handle;

  rv = (*fp)(argc-2, argv+2);

  return rv;
}
