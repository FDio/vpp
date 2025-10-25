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
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif /* __FreeBSD__ */
#include <sched.h>
#include <fcntl.h>
#include <getopt.h>

#include <vppinfra/clib.h>
#include <vppinfra/cpu.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/unix.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/threads.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vpp/app/version.h>
#include <vpp/vnet/config.h>
#include <vlibmemory/memclnt.api_enum.h> /* To get the last static message id */
#include <limits.h>

/*
 * Load plugins from /usr/lib/vpp_plugins by default
 */
char *vlib_plugin_path = NULL;
char *vlib_plugin_app_version = VPP_BUILD_VER;
char *vat_plugin_path = NULL;
char *vlib_default_runtime_dir = "vpp";

static void
vpp_find_plugin_path ()
{
  extern char *vat_plugin_path;
  char *p;
  u8 *s, *path;

  /* find executable path */
  path = os_get_exec_path ();

  if (!path)
    return;

  /* add null termination */
  vec_add1 (path, 0);

  /* strip filename */
  if ((p = strrchr ((char *) path, '/')) == 0)
    goto done;
  *p = 0;

  /* strip bin/ */
  if ((p = strrchr ((char *) path, '/')) == 0)
    goto done;
  *p = 0;

  s = format (0, "%s/" CLIB_LIB_DIR "/vpp_plugins", path, path);
  vec_add1 (s, 0);
  vlib_plugin_path = (char *) s;

  s = format (0, "%s/" CLIB_LIB_DIR "/vpp_api_test_plugins", path, path);
  vec_add1 (s, 0);
  vat_plugin_path = (char *) s;

done:
  vec_free (path);
}

static void
print_help (const char *progname)
{
  fformat (
    stdout,
    "Usage: %s [options] [startup configuration]\n"
    "  -c, --config <file>         Read startup configuration from file\n"
    "  -i, --interactive           Run in interactive mode\n"
    "  -v, --version               Print version information and exit\n"
    "  -h, --help                  Show this help message and exit\n",
    progname);
}

static void
print_version (void)
{
  fformat (stdout, "vpp v%s built by %s on %s at %s\n", VPP_BUILD_VER,
	   VPP_BUILD_USER, VPP_BUILD_HOST, VPP_BUILD_DATE);
}

int
main (int argc, char *argv[])
{
  int i;
  void vl_msg_api_set_first_available_msg_id (u16);
  uword main_heap_size = (1ULL << 30);
  clib_mem_page_sz_t main_heap_log2_page_sz = CLIB_MEM_PAGE_SZ_DEFAULT;
  clib_mem_page_sz_t default_log2_hugepage_sz = CLIB_MEM_PAGE_SZ_UNKNOWN;
  const size_t config_max_size = 1ULL << 18;
  unformat_input_t input, sub_input;
  u8 *s = 0, *v = 0, *config;
  u32 main_core = ~0;
  int cpu_translate = 0;
  cpu_set_t cpuset;
  void *main_heap;
  u32 cfg_len = 0;
  char *config_file = 0;
  int opt;
  int config_arg_index = 1;

  const struct option long_options[] = {
    { "config", required_argument, 0, 'c' },
    { "version", no_argument, 0, 'v' },
    { "interactive", no_argument, 0, 'i' },
    { "help", no_argument, 0, 'h' },
    {},
  };

  clib_mem_init (0, 1 << 20);

  opterr = 0;
  while ((opt = getopt_long (argc, argv, "c:ivh", long_options, 0)) != -1)
    {
      switch (opt)
	{
	case 'c':
	  config_file = optarg;
	  break;
	case 'i':
	  unix_main.flags |= UNIX_FLAG_INTERACTIVE;
	  break;
	case 'v':
	  print_version ();
	  return 0;
	case 'h':
	  print_help (argv[0]);
	  return 0;
	case '?':
	  if (optopt == 'c')
	    fprintf (stderr, "%s: option '-%c' requires an argument\n",
		     argv[0], optopt);
	  else if (optopt)
	    fprintf (stderr, "%s: unrecognized option '-%c'\n", argv[0],
		     optopt);
	  else if (optind > 0 && optind <= argc)
	    fprintf (stderr, "%s: unrecognized option '%s'\n", argv[0],
		     argv[optind - 1]);
	  else
	    fprintf (stderr, "%s: unrecognized option\n", argv[0]);
	  print_help (argv[0]);
	  return 1;
	default:
	  break;
	}
    }

  /* map some memory for config so it survives main heap swap */
  config = mmap (0, config_max_size, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (config == MAP_FAILED)
    {
      fprintf (stderr, "Failed to allocate config buffer\n");
      return 1;
    }

  config_arg_index = optind;

  if (config_file)
    {
      int fd = open (config_file, O_RDONLY);
      ssize_t n_read;
      u8 buf[4096];
      int skip_line = 0;

      if (fd < 0)
	{
	  fprintf (stderr, "failed to open configuration file '%s'\n",
		   config_file);
	  munmap (config, config_max_size);
	  return 1;
	}

      while ((n_read = read (fd, buf, sizeof (buf))) > 0)
	{
	  for (u32 j = 0; j < n_read; j++)
	    {
	      u8 c = buf[j];

	      if (skip_line)
		{
		  if (c == '\n' || c == '\r')
		    {
		      skip_line = 0;
		      c = ' ';
		    }
		  else
		    continue;
		}
	      else if (c == '#')
		{
		  skip_line = 1;
		  continue;
		}

	      if (c == '\r' || c == '\n' || c == '\t')
		c = ' ';

	      if (c == ' ')
		{
		  if (cfg_len == 0 || config[cfg_len - 1] == ' ')
		    continue;
		}

	      if (cfg_len + 1 >= config_max_size)
		{
		  fprintf (stderr, "startup config file is too large\n");
		  close (fd);
		  munmap (config, config_max_size);
		  return 1;
		}

	      config[cfg_len++] = c;
	    }
	}

      close (fd);

      if (n_read < 0)
	{
	  fprintf (stderr, "failed to read startup config file '%s'\n",
		   config_file);
	  munmap (config, config_max_size);
	  return 1;
	}

      if (cfg_len && config[cfg_len - 1] == ' ')
	cfg_len--;

      config[cfg_len] = 0;
    }
  else
    {
      /* construct config out of argvs */
      for (i = config_arg_index; i < argc; i++)
	cfg_len += sprintf ((char *) (config + cfg_len), "%s%s",
			    cfg_len ? " " : "", argv[i]);
      config[cfg_len] = 0;
    }

  unformat_init_string (&input, (const char *) config, (int) cfg_len);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "plugin_path %s", &vlib_plugin_path))
	;
      else if (unformat (&input, "test_plugin_path %s", &vat_plugin_path))
	;
      else if (unformat (&input, "memory %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub_input, "default-hugepage-size %U",
			    unformat_log2_page_size,
			    &default_log2_hugepage_sz))
		;
	      else if (unformat (&sub_input, "main-heap-size %U",
				 unformat_memory_size, &main_heap_size))
		;
	      else if (unformat (&sub_input, "main-heap-page-size %U",
				 unformat_log2_page_size,
				 &main_heap_log2_page_sz))
		;
	      else if (unformat (&sub_input, "%v", &v))
		vec_reset_length (v);
	    }
	  unformat_free (&sub_input);
	}
      else if (unformat (&input, "cpu %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  if (unformat (&sub_input, "main-core %u", &main_core))
	    ;
	  if (unformat (&sub_input, "relative"))
	    cpu_translate = 1;
	  else if (unformat (&sub_input, "%v", &v))
	    vec_reset_length (v);
	}
      else if (unformat (&input, "unix %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub_input, "interactive"))
		unix_main.flags |= UNIX_FLAG_INTERACTIVE;
	      if (unformat (&sub_input, "nosyslog"))
		unix_main.flags |= UNIX_FLAG_NOSYSLOG;
	      else if (unformat (&sub_input, "%v", &v))
		vec_reset_length (v);
	    }
	  unformat_free (&sub_input);
	}
      else if (!unformat (&input, "%s %v", &s, &v))
	break;

      vec_reset_length (s);
      vec_reset_length (v);
    }
  vec_free (s);
  vec_free (v);

  unformat_free (&input);

  int translate_main_core =
    os_translate_cpu_to_affinity_bitmap ((int) main_core);

  if (cpu_translate && main_core != ~0)
    {
      if (translate_main_core == -1)
	clib_error ("cpu %u is not available to be used"
		    " for the main thread in relative mode",
		    main_core);
      main_core = translate_main_core;
    }

  /* if main thread affinity is unspecified, set to current running cpu */
  if (main_core == ~0)
    main_core = sched_getcpu ();

  /* set process affinity for main thread */
  if (main_core != ~0)
    {
      CPU_ZERO (&cpuset);
      CPU_SET (main_core, &cpuset);
      if (pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t),
				  &cpuset))
	{
	  clib_unix_error (
	    "pthread_setaffinity_np() on cpu %d failed for main thread",
	    main_core);
	}
    }

  clib_mem_destroy ();

  main_heap =
    clib_mem_init_with_page_size (main_heap_size, main_heap_log2_page_sz);

  if (!main_heap)
    {
      fprintf (stderr, "main heap allocation failure: %s (%d)\n",
	       strerror (errno), errno);
      munmap (config, config_max_size);
      return 1;
    }

  vec_add (s, config, cfg_len);
  munmap (config, config_max_size);
  config = s;
  s = 0;

  /* Figure out which numa runs the main thread */
  __os_numa_index = clib_get_current_numa_node ();

  /* Set up the plugin message ID allocator right now... */
  vl_msg_api_set_first_available_msg_id (VL_MSG_MEMCLNT_LAST + 1);

  if (default_log2_hugepage_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    clib_mem_set_log2_default_hugepage_size (default_log2_hugepage_sz);

  /* and use the main heap as that numa's numa heap */
  clib_mem_set_per_numa_heap (main_heap);
  vlib_main_init ();

#if VPP_API_TEST_BUILTIN > 0
  void vat_plugin_hash_create (void);
#endif

  if (CLIB_DEBUG > 0)
    vlib_unix_cli_set_prompt ("DBGvpp# ");
  else
    vlib_unix_cli_set_prompt ("vpp# ");

  /* Turn off network stack components which we don't want */
  vlib_mark_init_function_complete (vm, srp_init);

  /*
   * Create the binary api plugin hashes before loading plugins
   */
#if VPP_API_TEST_BUILTIN > 0
  vat_plugin_hash_create ();
#endif

  if (!vlib_plugin_path)
    vpp_find_plugin_path ();

  return vlib_unix_main (argc, argv, config);
}

static clib_error_t *
memory_config (vlib_main_t *vm, unformat_input_t *input)
{
  return 0;
}

static clib_error_t *
plugin_path_config (vlib_main_t *vm, unformat_input_t *input)
{
  return 0;
}

static clib_error_t *
test_plugin_path_config (vlib_main_t *vm, unformat_input_t *input)
{
  return 0;
}

VLIB_CONFIG_FUNCTION (memory_config, "memory");
VLIB_CONFIG_FUNCTION (plugin_path_config, "plugin_path");
VLIB_CONFIG_FUNCTION (test_plugin_path_config, "test_plugin_path");

void vl_msg_api_post_mortem_dump (void);
void vlib_post_mortem_dump (void);

void
os_panic (void)
{
  vl_msg_api_post_mortem_dump ();
  vlib_post_mortem_dump ();
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
      vlib_post_mortem_dump ();
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

#include <vppinfra/bihash_8_8.h>

static clib_error_t *
show_bihash_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int i;
  clib_bihash_8_8_t *h;
  int verbose = 0;

  if (unformat (input, "verbose"))
    verbose = 1;

  for (i = 0; i < vec_len (clib_all_bihashes); i++)
    {
      h = (clib_bihash_8_8_t *) clib_all_bihashes[i];
      vlib_cli_output (vm, "\n%U", h->fmt_fn, h, verbose);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_bihash_command, static) =
{
  .path = "show bihash",
  .short_help = "show bihash",
  .function = show_bihash_command_fn,
};

#ifdef CLIB_SANITIZE_ADDR
/* default options for Address Sanitizer */
const char *
__asan_default_options (void)
{
  return VPP_SANITIZE_ADDR_OPTIONS;
}
#endif /* CLIB_SANITIZE_ADDR */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
