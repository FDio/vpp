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

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>

#include <vppinfra/cpu.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vpp/app/version.h>
#include <vpp/api/vpe_msg_enum.h>
#include <limits.h>

/*
 * Load plugins from /usr/lib/vpp_plugins by default
 */
char *vlib_plugin_path = NULL;
char *vlib_plugin_app_version = VPP_BUILD_VER;

static void
vpp_find_plugin_path ()
{
  extern char *vat_plugin_path;
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

  s = format (0, "%s/lib/vpp_plugins", path);
  vec_add1 (s, 0);
  vlib_plugin_path = (char *) s;

  s = format (0, "%s/lib/vpp_api_test_plugins", path);
  vec_add1 (s, 0);
  vat_plugin_path = (char *) s;
}

static void
vpe_main_init (vlib_main_t * vm)
{
  void vat_plugin_hash_create (void);

  if (CLIB_DEBUG > 0)
    vlib_unix_cli_set_prompt ("DBGvpp# ");
  else
    vlib_unix_cli_set_prompt ("vpp# ");

  /* Turn off network stack components which we don't want */
  vlib_mark_init_function_complete (vm, srp_init);

  /*
   * Create the binary api plugin hashes before loading plugins
   */
  vat_plugin_hash_create ();

  if(!vlib_plugin_path)
    vpp_find_plugin_path ();
}

/*
 * Default path for runtime data
 */
char *vlib_default_runtime_dir = "vpp";

int
main (int argc, char *argv[])
{
  int i;
  vlib_main_t *vm = &vlib_global_main;
  void vl_msg_api_set_first_available_msg_id (u16);
  uword main_heap_size = (1ULL << 30);
  u8 *sizep;
  u32 size;
  int main_core = 1;
  cpu_set_t cpuset;

#if __x86_64__
  CLIB_UNUSED (const char *msg)
    = "ERROR: This binary requires CPU with %s extensions.\n";
#define _(a,b)                                  \
    if (!clib_cpu_supports_ ## a ())            \
      {                                         \
	fprintf(stderr, msg, b);                \
	exit(1);                                \
      }

#if __AVX2__
  _(avx2, "AVX2")
#endif
#if __AVX__
    _(avx, "AVX")
#endif
#if __SSE4_2__
    _(sse42, "SSE4.2")
#endif
#if __SSE4_1__
    _(sse41, "SSE4.1")
#endif
#if __SSSE3__
    _(ssse3, "SSSE3")
#endif
#if __SSE3__
    _(sse3, "SSE3")
#endif
#undef _
#endif
    /*
     * Load startup config from file.
     * usage: vpp -c /etc/vpp/startup.conf
     */
    if ((argc == 3) && !strncmp (argv[1], "-c", 2))
    {
      FILE *fp;
      char inbuf[4096];
      int argc_ = 1;
      char **argv_ = NULL;
      char *arg = NULL;
      char *p;

      fp = fopen (argv[2], "r");
      if (fp == NULL)
	{
	  fprintf (stderr, "open configuration file '%s' failed\n", argv[2]);
	  return 1;
	}
      argv_ = calloc (1, sizeof (char *));
      if (argv_ == NULL)
	{
	  fclose (fp);
	  return 1;
	}
      arg = strndup (argv[0], 1024);
      if (arg == NULL)
	{
	  fclose (fp);
	  free (argv_);
	  return 1;
	}
      argv_[0] = arg;

      while (1)
	{
	  if (fgets (inbuf, 4096, fp) == 0)
	    break;
	  p = strtok (inbuf, " \t\n");
	  while (p != NULL)
	    {
	      if (*p == '#')
		break;
	      argc_++;
	      char **tmp = realloc (argv_, argc_ * sizeof (char *));
	      if (tmp == NULL)
		return 1;
	      argv_ = tmp;
	      arg = strndup (p, 1024);
	      if (arg == NULL)
		return 1;
	      argv_[argc_ - 1] = arg;
	      p = strtok (NULL, " \t\n");
	    }
	}

      fclose (fp);

      char **tmp = realloc (argv_, (argc_ + 1) * sizeof (char *));
      if (tmp == NULL)
	return 1;
      argv_ = tmp;
      argv_[argc_] = NULL;

      argc = argc_;
      argv = argv_;
    }

  /*
   * Look for and parse the "heapsize" config parameter.
   * Manual since none of the clib infra has been bootstrapped yet.
   *
   * Format: heapsize <nn>[mM][gG]
   */

  for (i = 1; i < (argc - 1); i++)
    {
      if (!strncmp (argv[i], "plugin_path", 11))
	{
	  if (i < (argc - 1))
	    vlib_plugin_path = argv[++i];
	}
      else if (!strncmp (argv[i], "heapsize", 8))
	{
	  sizep = (u8 *) argv[i + 1];
	  size = 0;
	  while (*sizep >= '0' && *sizep <= '9')
	    {
	      size *= 10;
	      size += *sizep++ - '0';
	    }
	  if (size == 0)
	    {
	      fprintf
		(stderr,
		 "warning: heapsize parse error '%s', use default %lld\n",
		 argv[i], (long long int) main_heap_size);
	      goto defaulted;
	    }

	  main_heap_size = size;

	  if (*sizep == 'g' || *sizep == 'G')
	    main_heap_size <<= 30;
	  else if (*sizep == 'm' || *sizep == 'M')
	    main_heap_size <<= 20;
	}
      else if (!strncmp (argv[i], "main-core", 9))
	{
	  if (i < (argc - 1))
	    {
	      errno = 0;
	      unsigned long x = strtol (argv[++i], 0, 0);
	      if (errno == 0)
		main_core = x;
	    }
	}
    }

defaulted:

  /* set process affinity for main thread */
  CPU_ZERO (&cpuset);
  CPU_SET (main_core, &cpuset);
  pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);

  /* Set up the plugin message ID allocator right now... */
  vl_msg_api_set_first_available_msg_id (VL_MSG_FIRST_AVAILABLE);

  /* Allocate main heap */
  if (clib_mem_init_thread_safe (0, main_heap_size))
    {
      vm->init_functions_called = hash_create (0, /* value bytes */ 0);
      vpe_main_init (vm);
      return vlib_unix_main (argc, argv);
    }
  else
    {
      {
	int rv __attribute__ ((unused)) =
	  write (2, "Main heap allocation failure!\r\n", 31);
      }
      return 1;
    }
}

static clib_error_t *
heapsize_config (vlib_main_t * vm, unformat_input_t * input)
{
  u32 junk;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%dm", &junk)
	  || unformat (input, "%dM", &junk)
	  || unformat (input, "%dg", &junk) || unformat (input, "%dG", &junk))
	return 0;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (heapsize_config, "heapsize");

static clib_error_t *
plugin_path_config (vlib_main_t * vm, unformat_input_t * input)
{
  u8 *junk;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%s", &junk))
	{
	  vec_free (junk);
	  return 0;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (plugin_path_config, "plugin_path");

void vl_msg_api_post_mortem_dump (void);
void elog_post_mortem_dump (void);

void
os_panic (void)
{
  vl_msg_api_post_mortem_dump ();
  elog_post_mortem_dump ();
  abort ();
}

void vhost_user_unmap_all (void) __attribute__ ((weak));
void
vhost_user_unmap_all (void)
{
}

void
os_exit (int code)
{
  static int recursion_block;

  if (code)
    {
      if (recursion_block)
	abort ();

      recursion_block = 1;

      vl_msg_api_post_mortem_dump ();
      elog_post_mortem_dump ();
      vhost_user_unmap_all ();
      abort ();
    }
  exit (code);
}

#ifdef BARRIER_TRACING
void
vl_msg_api_barrier_trace_context (const char *context)
{
  vlib_worker_threads[0].barrier_context = context;
}
#endif

void
vl_msg_api_barrier_sync (void)
{
  vlib_worker_thread_barrier_sync (vlib_get_main ());
}

void
vl_msg_api_barrier_release (void)
{
  vlib_worker_thread_barrier_release (vlib_get_main ());
}

/* This application needs 1 thread stack for the stats pthread */
u32
vlib_app_num_thread_stacks_needed (void)
{
  return 1;
}

/*
 * Depending on the configuration selected above,
 * it may be necessary to generate stub graph nodes.
 * It is never OK to ignore "node 'x' refers to unknown node 'y'
 * messages!
 */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
