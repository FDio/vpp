/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
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

#include <vcl/vcl_private.h>

/* NOTE: _vppcom_main is only used until the heap is allocated.
 *       Do not access it directly -- use vcm which will point to
 *       the heap allocated copy after init.
 */
static vppcom_main_t _vppcom_main = {
  .debug = VPPCOM_DEBUG_INIT,
  .is_init = 0,
  .app_index = ~0,
};

vppcom_main_t *vcm = &_vppcom_main;

void
vppcom_cfg_init (vppcom_cfg_t * vcl_cfg)
{
  ASSERT (vcl_cfg);

  vcl_cfg->heapsize = (256ULL << 20);
  vcl_cfg->max_workers = 16;
  vcl_cfg->vpp_api_q_length = 1024;
  vcl_cfg->segment_baseva = HIGH_SEGMENT_BASEVA;
  vcl_cfg->segment_size = (256 << 20);
  vcl_cfg->add_segment_size = (128 << 20);
  vcl_cfg->preallocated_fifo_pairs = 8;
  vcl_cfg->rx_fifo_size = (1 << 20);
  vcl_cfg->tx_fifo_size = (1 << 20);
  vcl_cfg->event_queue_size = 2048;
  vcl_cfg->listen_queue_size = CLIB_CACHE_LINE_BYTES / sizeof (u32);
  vcl_cfg->app_timeout = 10 * 60.0;
  vcl_cfg->session_timeout = 10 * 60.0;
  vcl_cfg->accept_timeout = 60.0;
  vcl_cfg->event_ring_size = (128 << 10);
  vcl_cfg->event_log_path = "/dev/shm";
}

#define VCFG_DBG(_lvl, _fmt, _args...) 			\
{							\
  if (vcm->debug > _lvl) 				\
    fprintf (stderr, _fmt "\n", ##_args);		\
}
void
vppcom_cfg_heapsize (char *conf_fname)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  FILE *fp;
  char inbuf[4096];
  int argc = 1;
  char **argv = NULL;
  char *arg = NULL;
  char *p;
  int i;
  u8 *sizep;
  u32 size;
  void *vcl_mem;
  void *heap;

  fp = fopen (conf_fname, "r");
  if (fp == NULL)
    {
      VCFG_DBG (0, "VCL<%d>: using default heapsize %lu (0x%lx)",
		getpid (), (unsigned long) vcl_cfg->heapsize,
		(unsigned long) vcl_cfg->heapsize);
      goto defaulted;
    }

  argv = calloc (1, sizeof (char *));
  if (argv == NULL)
    {
      VCFG_DBG (0, "VCL<%d>: calloc failed, using default heapsize %lu"
		" (0x%lx)", getpid (), (unsigned long) vcl_cfg->heapsize,
		(unsigned long) vcl_cfg->heapsize);
      goto defaulted;
    }

  while (1)
    {
      if (fgets (inbuf, 4096, fp) == 0)
	break;
      p = strtok (inbuf, " \t\n");
      while (p != NULL)
	{
	  if (*p == '#')
	    break;
	  argc++;
	  char **tmp = realloc (argv, argc * sizeof (char *));
	  if (tmp == NULL)
	    {
	      VCFG_DBG (0, "VCL<%d>: realloc failed, using default "
			"heapsize %lu (0x%lx)", getpid (),
			(unsigned long) vcl_cfg->heapsize,
			(unsigned long) vcl_cfg->heapsize);
	      goto defaulted;
	    }
	  argv = tmp;
	  arg = strndup (p, 1024);
	  if (arg == NULL)
	    {
	      VCFG_DBG (0, "VCL<%d>: strndup failed, using default "
			"heapsize %lu (0x%lx)", getpid (),
			(unsigned long) vcl_cfg->heapsize,
			(unsigned long) vcl_cfg->heapsize);
	      goto defaulted;
	    }
	  argv[argc - 1] = arg;
	  p = strtok (NULL, " \t\n");
	}
    }

  fclose (fp);
  fp = NULL;

  char **tmp = realloc (argv, (argc + 1) * sizeof (char *));
  if (tmp == NULL)
    {
      VCFG_DBG (0, "VCL<%d>: realloc failed, using default heapsize %lu "
		"(0x%lx)", getpid (), (unsigned long) vcl_cfg->heapsize,
		(unsigned long) vcl_cfg->heapsize);
      goto defaulted;
    }
  argv = tmp;
  argv[argc] = NULL;

  /*
   * Look for and parse the "heapsize" config parameter.
   * Manual since none of the clib infra has been bootstrapped yet.
   *
   * Format: heapsize <nn>[mM][gG]
   */

  for (i = 1; i < (argc - 1); i++)
    {
      if (!strncmp (argv[i], "heapsize", 8))
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
	      VCFG_DBG (0, "VCL<%d>: parse error '%s %s', using default "
			"heapsize %lu (0x%lx)", getpid (), argv[i],
			argv[i + 1], (unsigned long) vcl_cfg->heapsize,
			(unsigned long) vcl_cfg->heapsize);
	      goto defaulted;
	    }

	  if (*sizep == 'g' || *sizep == 'G')
	    vcl_cfg->heapsize = size << 30;
	  else if (*sizep == 'm' || *sizep == 'M')
	    vcl_cfg->heapsize = size << 20;
	  else
	    {
	      VCFG_DBG (0, "VCL<%d>: parse error '%s %s', using default "
			"heapsize %lu (0x%lx)", getpid (), argv[i],
			argv[i + 1], (unsigned long) vcl_cfg->heapsize,
			(unsigned long) vcl_cfg->heapsize);
	      goto defaulted;
	    }
	}
      free (argv[i]);
    }

defaulted:
  if (fp != NULL)
    fclose (fp);
  if (argv != NULL)
    free (argv);

  vcl_mem = mmap (0, vcl_cfg->heapsize, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (vcl_mem == MAP_FAILED)
    {
      VCFG_DBG (0, "VCL<%d>: ERROR: mmap(0, %lu == 0x%lx, "
		"PROT_READ | PROT_WRITE,MAP_SHARED | MAP_ANONYMOUS, "
		"-1, 0) failed!", getpid (),
		(unsigned long) vcl_cfg->heapsize,
		(unsigned long) vcl_cfg->heapsize);
      ASSERT (vcl_mem != MAP_FAILED);
      return;
    }
  heap = clib_mem_init_thread_safe (vcl_mem, vcl_cfg->heapsize);
  if (!heap)
    {
      fprintf (stderr, "VCL<%d>: ERROR: clib_mem_init() failed!", getpid ());
      ASSERT (heap);
      return;
    }
  vcl_mem = clib_mem_alloc (sizeof (_vppcom_main));
  if (!vcl_mem)
    {
      clib_warning ("VCL<%d>: ERROR: clib_mem_alloc() failed!", getpid ());
      ASSERT (vcl_mem);
      return;
    }

  clib_memcpy (vcl_mem, &_vppcom_main, sizeof (_vppcom_main));
  vcm = vcl_mem;

  VCFG_DBG (0, "VCL<%d>: allocated VCL heap = %p, size %lu (0x%lx)",
	    getpid (), heap, (unsigned long) vcl_cfg->heapsize,
	    (unsigned long) vcl_cfg->heapsize);
}

void
vppcom_cfg_read_file (char *conf_fname)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  int fd;
  unformat_input_t _input, *input = &_input;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 vc_cfg_input = 0, *chroot_path;
  struct stat s;
  u32 uid, gid, q_len;

  fd = open (conf_fname, O_RDONLY);
  if (fd < 0)
    {
      VCFG_DBG (0, "VCL<%d>: using default configuration.", getpid ());
      goto file_done;
    }

  if (fstat (fd, &s) < 0)
    {
      VCFG_DBG (0, "VCL<%d>: failed to stat `%s' using default configuration",
		getpid (), conf_fname);
      goto file_done;
    }

  if (!(S_ISREG (s.st_mode) || S_ISLNK (s.st_mode)))
    {
      VCFG_DBG (0, "VCL<%d>: not a regular file `%s', using default "
		"configuration", getpid (), conf_fname);
      goto file_done;
    }

  unformat_init_clib_file (input, fd);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      (void) unformat_user (input, unformat_line_input, line_input);
      unformat_skip_white_space (line_input);

      if (unformat (line_input, "vcl {"))
	{
	  vc_cfg_input = 1;
	  unformat_free (line_input);
	  continue;
	}

      if (vc_cfg_input)
	{
	  if (unformat (line_input, "heapsize %U", unformat_memory_size,
			&vcl_cfg->heapsize))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured heapsize %lu", getpid (),
			(unsigned long) vcl_cfg->heapsize);
	    }
	  else
	    if (unformat
		(line_input, "max-workers %u", &vcl_cfg->max_workers))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured max-workers %u", getpid (),
			vcl_cfg->max_workers);
	    }
	  else if (unformat (line_input, "api-prefix %s", &chroot_path))
	    {
	      vec_terminate_c_string (chroot_path);
	      if (vcl_cfg->vpp_api_filename)
		vec_free (vcl_cfg->vpp_api_filename);
	      vcl_cfg->vpp_api_filename = format (0, "/%s-vpe-api%c",
						  chroot_path, 0);
	      vl_set_memory_root_path ((char *) chroot_path);

	      VCFG_DBG (0, "VCL<%d>: configured api-prefix (%s) and api "
			"filename (%s)", getpid (), chroot_path,
			vcl_cfg->vpp_api_filename);
	      chroot_path = 0;	/* Don't vec_free() it! */
	    }
	  else if (unformat (line_input, "api-socket-name %s",
			     &vcl_cfg->vpp_api_socket_name))
	    {
	      vec_terminate_c_string (vcl_cfg->vpp_api_socket_name);
	      VCFG_DBG (0, "VCL<%d>: configured api-socket-name (%s)",
			getpid (), vcl_cfg->vpp_api_socket_name);
	    }
	  else if (unformat (line_input, "vpp-api-q-length %d", &q_len))
	    {
	      if (q_len < vcl_cfg->vpp_api_q_length)
		{
		  fprintf (stderr,
			   "VCL<%d>: ERROR: configured vpp-api-q-length "
			   "(%u) is too small! Using default: %u ", getpid (),
			   q_len, vcl_cfg->vpp_api_q_length);
		}
	      else
		{
		  vcl_cfg->vpp_api_q_length = q_len;

		  VCFG_DBG (0, "VCL<%d>: configured vpp-api-q-length %u",
			    getpid (), vcl_cfg->vpp_api_q_length);
		}
	    }
	  else if (unformat (line_input, "uid %d", &uid))
	    {
	      vl_set_memory_uid (uid);
	      VCFG_DBG (0, "VCL<%d>: configured uid %d", getpid (), uid);
	    }
	  else if (unformat (line_input, "gid %d", &gid))
	    {
	      vl_set_memory_gid (gid);
	      VCFG_DBG (0, "VCL<%d>: configured gid %d", getpid (), gid);
	    }
	  else if (unformat (line_input, "segment-baseva 0x%x",
			     &vcl_cfg->segment_baseva))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured segment_baseva 0x%lx",
			getpid (), (unsigned long) vcl_cfg->segment_baseva);
	    }
	  else if (unformat (line_input, "segment-size 0x%x",
			     &vcl_cfg->segment_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured segment_size 0x%x (%d)",
			getpid (), vcl_cfg->segment_size,
			vcl_cfg->segment_size);
	    }
	  else if (unformat (line_input, "segment-size %d",
			     &vcl_cfg->segment_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured segment_size %d (0x%x)",
			getpid (), vcl_cfg->segment_size,
			vcl_cfg->segment_size);
	    }
	  else if (unformat (line_input, "add-segment-size 0x%x",
			     &vcl_cfg->add_segment_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured add_segment_size 0x%x (%d)",
			getpid (), vcl_cfg->add_segment_size,
			vcl_cfg->add_segment_size);
	    }
	  else if (unformat (line_input, "add-segment-size %d",
			     &vcl_cfg->add_segment_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured add_segment_size %d (0x%x)",
			getpid (), vcl_cfg->add_segment_size,
			vcl_cfg->add_segment_size);
	    }
	  else if (unformat (line_input, "preallocated-fifo-pairs %d",
			     &vcl_cfg->preallocated_fifo_pairs))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured preallocated_fifo_pairs %d "
			"(0x%x)", getpid (), vcl_cfg->preallocated_fifo_pairs,
			vcl_cfg->preallocated_fifo_pairs);
	    }
	  else if (unformat (line_input, "rx-fifo-size 0x%lx",
			     &vcl_cfg->rx_fifo_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured rx_fifo_size 0x%x (%d)",
			getpid (), vcl_cfg->rx_fifo_size,
			vcl_cfg->rx_fifo_size);
	    }
	  else if (unformat (line_input, "rx-fifo-size %d",
			     &vcl_cfg->rx_fifo_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured rx_fifo_size %d (0x%x)",
			getpid (), vcl_cfg->rx_fifo_size,
			vcl_cfg->rx_fifo_size);
	    }
	  else if (unformat (line_input, "tx-fifo-size 0x%lx",
			     &vcl_cfg->tx_fifo_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured tx_fifo_size 0x%x (%d)",
			getpid (), vcl_cfg->tx_fifo_size,
			vcl_cfg->tx_fifo_size);
	    }
	  else if (unformat (line_input, "tx-fifo-size %ld",
			     &vcl_cfg->tx_fifo_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured tx_fifo_size %d (0x%x)",
			getpid (), vcl_cfg->tx_fifo_size,
			vcl_cfg->tx_fifo_size);
	    }
	  else if (unformat (line_input, "event-queue-size 0x%lx",
			     &vcl_cfg->event_queue_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured event_queue_size 0x%x (%d)",
			getpid (), vcl_cfg->event_queue_size,
			vcl_cfg->event_queue_size);
	    }
	  else if (unformat (line_input, "event-queue-size %ld",
			     &vcl_cfg->event_queue_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured event_queue_size %d (0x%x)",
			getpid (), vcl_cfg->event_queue_size,
			vcl_cfg->event_queue_size);
	    }
	  else if (unformat (line_input, "listen-queue-size 0x%lx",
			     &vcl_cfg->listen_queue_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured listen_queue_size 0x%x (%u)",
			getpid (), vcl_cfg->listen_queue_size,
			vcl_cfg->listen_queue_size);
	    }
	  else if (unformat (line_input, "listen-queue-size %ld",
			     &vcl_cfg->listen_queue_size))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured listen_queue_size %u (0x%x)",
			getpid (), vcl_cfg->listen_queue_size,
			vcl_cfg->listen_queue_size);
	    }
	  else if (unformat (line_input, "app-timeout %f",
			     &vcl_cfg->app_timeout))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured app_timeout %f",
			getpid (), vcl_cfg->app_timeout);
	    }
	  else if (unformat (line_input, "session-timeout %f",
			     &vcl_cfg->session_timeout))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured session_timeout %f",
			getpid (), vcl_cfg->session_timeout);
	    }
	  else if (unformat (line_input, "accept-timeout %f",
			     &vcl_cfg->accept_timeout))
	    {
	      VCFG_DBG (0, "VCL<%d>: configured accept_timeout %f",
			getpid (), vcl_cfg->accept_timeout);
	    }
	  else if (unformat (line_input, "app-proxy-transport-tcp"))
	    {
	      vcl_cfg->app_proxy_transport_tcp = 1;
	      VCFG_DBG (0, "VCL<%d>: configured app_proxy_transport_tcp (%d)",
			getpid (), vcl_cfg->app_proxy_transport_tcp);
	    }
	  else if (unformat (line_input, "app-proxy-transport-udp"))
	    {
	      vcl_cfg->app_proxy_transport_udp = 1;
	      VCFG_DBG (0, "VCL<%d>: configured app_proxy_transport_udp (%d)",
			getpid (), vcl_cfg->app_proxy_transport_udp);
	    }
	  else if (unformat (line_input, "app-scope-local"))
	    {
	      vcl_cfg->app_scope_local = 1;
	      VCFG_DBG (0, "VCL<%d>: configured app_scope_local (%d)",
			getpid (), vcl_cfg->app_scope_local);
	    }
	  else if (unformat (line_input, "app-scope-global"))
	    {
	      vcl_cfg->app_scope_global = 1;
	      VCFG_DBG (0, "VCL<%d>: configured app_scope_global (%d)",
			getpid (), vcl_cfg->app_scope_global);
	    }
	  else if (unformat (line_input, "namespace-secret %lu",
			     &vcl_cfg->namespace_secret))
	    {
	      VCFG_DBG (0,
			"VCL<%d>: configured namespace_secret %llu (0x%llx)",
			getpid (),
			(unsigned long long) vcl_cfg->namespace_secret,
			(unsigned long long) vcl_cfg->namespace_secret);
	    }
	  else if (unformat (line_input, "namespace-id %v",
			     &vcl_cfg->namespace_id))
	    {
	      u32 max_nsid_vec_len = vcl_max_nsid_len ();
	      u32 nsid_vec_len = vec_len (vcl_cfg->namespace_id);
	      if (nsid_vec_len > max_nsid_vec_len)
		{
		  _vec_len (vcl_cfg->namespace_id) = max_nsid_vec_len;
		  VCFG_DBG (0, "VCL<%d>: configured namespace_id is too long,"
			    " truncated to %d characters!",
			    getpid (), max_nsid_vec_len);
		}

	      VCFG_DBG (0, "VCL<%d>: configured namespace_id %s",
			getpid (), (char *) vcl_cfg->namespace_id);
	    }
	  else if (unformat (line_input, "use-mq-eventfd"))
	    {
	      vcl_cfg->use_mq_eventfd = 1;
	      VCFG_DBG (0, "VCL<%d>: configured with mq with eventfd",
			getpid ());
	    }
	  else if (unformat (line_input, "}"))
	    {
	      vc_cfg_input = 0;
	      VCFG_DBG (0, "VCL<%d>: completed parsing vppcom config!",
			getpid ());
	      unformat_free (line_input);
	      goto input_done;
	    }
	  else
	    {
	      if (line_input->buffer[line_input->index] != '#')
		{
		  clib_warning ("VCL<%d>: Unknown vppcom config option: '%s'",
				getpid (), (char *)
				&line_input->buffer[line_input->index]);
		}
	    }
	  unformat_free (line_input);
	}
    }

input_done:
  unformat_free (input);

file_done:
  if (fd >= 0)
    close (fd);
}

void
vppcom_cfg (vppcom_cfg_t * vcl_cfg)
{
  char *conf_fname, *env_var_str;

  vppcom_cfg_init (vcl_cfg);
  env_var_str = getenv (VPPCOM_ENV_DEBUG);
  if (env_var_str)
    {
      u32 tmp;
      if (sscanf (env_var_str, "%u", &tmp) != 1)
	{
	  VCFG_DBG (0, "VCL<%d>: WARNING: Invalid debug level specified "
		    "in the environment variable " VPPCOM_ENV_DEBUG
		    " (%s)!\n", getpid (), env_var_str);
	}
      else
	{
	  vcm->debug = tmp;
	  VCFG_DBG (0, "VCL<%d>: configured VCL debug level (%u) from "
		    VPPCOM_ENV_DEBUG "!", getpid (), vcm->debug);
	}
    }
  conf_fname = getenv (VPPCOM_ENV_CONF);
  if (!conf_fname)
    conf_fname = VPPCOM_CONF_DEFAULT;
  vppcom_cfg_heapsize (conf_fname);
  vppcom_cfg_read_file (conf_fname);

  env_var_str = getenv (VPPCOM_ENV_API_PREFIX);
  if (env_var_str)
    {
      if (vcl_cfg->vpp_api_filename)
	vec_free (vcl_cfg->vpp_api_filename);
      vcl_cfg->vpp_api_filename = format (0, "/%s-vpe-api%c", env_var_str, 0);
      vl_set_memory_root_path ((char *) env_var_str);

      VCFG_DBG (0, "VCL<%d>: configured api prefix (%s) and filename (%s) "
		"from " VPPCOM_ENV_API_PREFIX "!", getpid (), env_var_str,
		vcl_cfg->vpp_api_filename);
    }
  env_var_str = getenv (VPPCOM_ENV_APP_NAMESPACE_ID);
  if (env_var_str)
    {
      u32 ns_id_vec_len = strlen (env_var_str);

      vec_reset_length (vcm->cfg.namespace_id);
      vec_validate (vcm->cfg.namespace_id, ns_id_vec_len - 1);
      clib_memcpy (vcm->cfg.namespace_id, env_var_str, ns_id_vec_len);

      VCFG_DBG (0, "VCL<%d>: configured namespace_id (%s) from "
		VPPCOM_ENV_APP_NAMESPACE_ID "!", getpid (),
		(char *) vcm->cfg.namespace_id);
    }
  env_var_str = getenv (VPPCOM_ENV_APP_NAMESPACE_SECRET);
  if (env_var_str)
    {
      u64 tmp;
      if (sscanf (env_var_str, "%llu", (unsigned long long *) &tmp) != 1)
	{
	  VCFG_DBG (0, "VCL<%d>: WARNING: Invalid namespace secret specified"
		    " in the environment variable "
		    VPPCOM_ENV_APP_NAMESPACE_SECRET " (%s)!\n", getpid (),
		    env_var_str);
	}
      else
	{
	  vcm->cfg.namespace_secret = tmp;
	  VCFG_DBG (0, "VCL<%d>: configured namespace secret (%llu) from "
		    VPPCOM_ENV_APP_NAMESPACE_SECRET "!", getpid (),
		    (unsigned long long) vcm->cfg.namespace_secret);
	}
    }
  if (getenv (VPPCOM_ENV_APP_PROXY_TRANSPORT_TCP))
    {
      vcm->cfg.app_proxy_transport_tcp = 1;
      VCFG_DBG (0, "VCL<%d>: configured app_proxy_transport_tcp (%u) from "
		VPPCOM_ENV_APP_PROXY_TRANSPORT_TCP "!", getpid (),
		vcm->cfg.app_proxy_transport_tcp);
    }
  if (getenv (VPPCOM_ENV_APP_PROXY_TRANSPORT_UDP))
    {
      vcm->cfg.app_proxy_transport_udp = 1;
      VCFG_DBG (0, "VCL<%d>: configured app_proxy_transport_udp (%u) from "
		VPPCOM_ENV_APP_PROXY_TRANSPORT_UDP "!", getpid (),
		vcm->cfg.app_proxy_transport_udp);
    }
  if (getenv (VPPCOM_ENV_APP_SCOPE_LOCAL))
    {
      vcm->cfg.app_scope_local = 1;
      VCFG_DBG (0, "VCL<%d>: configured app_scope_local (%u) from "
		VPPCOM_ENV_APP_SCOPE_LOCAL "!", getpid (),
		vcm->cfg.app_scope_local);
    }
  if (getenv (VPPCOM_ENV_APP_SCOPE_GLOBAL))
    {
      vcm->cfg.app_scope_global = 1;
      VCFG_DBG (0, "VCL<%d>: configured app_scope_global (%u) from "
		VPPCOM_ENV_APP_SCOPE_GLOBAL "!", getpid (),
		vcm->cfg.app_scope_global);
    }
  env_var_str = getenv (VPPCOM_ENV_VPP_API_SOCKET);
  if (env_var_str)
    {
      vcm->cfg.vpp_api_socket_name = format (0, "%s%c", env_var_str, 0);
      VCFG_DBG (0, "VCL<%d>: configured api-socket-name (%s)", getpid (),
		vcl_cfg->vpp_api_socket_name);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
