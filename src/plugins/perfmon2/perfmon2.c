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

#include <vnet/vnet.h>
#include <perfmon/perfmon.h>
#include <perfmon/perfmon_intel.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon2/perfmon2.h>
#include <perfmon2/intel.h>

perfmon2_main_t perfmon2_main;

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_default_log, static) = {
  .class_name = "perfmon2",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_default_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_default_log.class, fmt, __VA_ARGS__)

static_always_inline void
perfmon2_read_pmcs (perfmon2_thread_t * pt, u64 * counters)
{
  switch (pt->n_events)
    {
    case 7:
      counters[6] = _rdpmc (pt->pmc_index[6]);
    case 6:
      counters[5] = _rdpmc (pt->pmc_index[5]);
    case 5:
      counters[4] = _rdpmc (pt->pmc_index[4]);
    case 4:
      counters[3] = _rdpmc (pt->pmc_index[3]);
    case 3:
      counters[2] = _rdpmc (pt->pmc_index[2]);
    case 2:
      counters[1] = _rdpmc (pt->pmc_index[1]);
    case 1:
      counters[0] = _rdpmc (pt->pmc_index[0]);
      break;
    default:
      return;
    }
}

static inline int
perfmon2_calc_pmc_index (perfmon2_thread_t * pt, int i)
{
  return (int) (pt->mmap_pages[i]->index + pt->mmap_pages[i]->offset);
}

static void
perfmon2_pre_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);

  switch (pt->n_events)
    {
    case 7:
      pt->pmc_index[6] = perfmon2_calc_pmc_index (pt, 6);
    case 6:
      pt->pmc_index[5] = perfmon2_calc_pmc_index (pt, 5);
    case 5:
      pt->pmc_index[4] = perfmon2_calc_pmc_index (pt, 4);
    case 4:
      pt->pmc_index[3] = perfmon2_calc_pmc_index (pt, 3);
    case 3:
      pt->pmc_index[2] = perfmon2_calc_pmc_index (pt, 2);
    case 2:
      pt->pmc_index[1] = perfmon2_calc_pmc_index (pt, 1);
    case 1:
      pt->pmc_index[0] = perfmon2_calc_pmc_index (pt, 0);
      break;
    default:
      return;
    }

  perfmon2_read_pmcs (pt, pt->node_pre_counters);
}

static void
perfmon2_post_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, uword n)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);
  u64 c[PERF_MAX_EVENTS];
  perfmon2_read_pmcs (pt, c);
  fformat (stderr, "%s: thread %u\n", __func__, vm->thread_index);
}


void
vlib_node_add_pre_dispatch_cb (vlib_main_t * vm,
			       vlib_node_pre_dispatch_cb_fn_t * cb)
{
  vec_add1 (vm->pre_dispatch_cb_fn, cb);
}

void
vlib_node_add_post_dispatch_cb (vlib_main_t * vm,
				vlib_node_post_dispatch_cb_fn_t * cb)
{
  vec_add1 (vm->post_dispatch_cb_fn, cb);
}

typedef struct
{
  u64 code[PERF_MAX_EVENTS];
  int n_events;
} perfmon2_events_t;

static clib_error_t *
perfmon2_event_start (vlib_main_t * vm, perfmon2_events_t * ev)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);
  clib_error_t *err = 0;
  int fd;

  pm->group_fd = -1;

  for (int i = 0; i < ev->n_events; i++)
    {
      struct perf_event_attr pe = {
	.size = sizeof (struct perf_event_attr),
	.type = PERF_TYPE_RAW,
	.config = pm->platform->config_by_event_index[ev->code[i]],
	.disabled = 1,
	.exclude_kernel = 1,
	.exclude_hv = 1,
      };

      fd = syscall (__NR_perf_event_open, &pe, /* pid */ 0, /* cpu */ -1,
		    /* group_fd */ pm->group_fd, /* flags */ 0);

      if (fd == -1)
	{
	  err = clib_error_return_unix (0, "perf_event_open");
	  goto error;
	}

      pt->mmap_pages[i] = mmap (0, clib_mem_get_page_size (), PROT_READ,
				MAP_SHARED, fd, 0);

      if (pt->mmap_pages[i] == MAP_FAILED)
	{
	  err = clib_error_return_unix (0, "mmap");
	  goto error;
	}

      if (pm->group_fd == -1)
	pm->group_fd = fd;
    }

  if (ioctl (pm->group_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) == -1)
    {
      err = clib_error_return_unix (0, "ioctl(PERF_EVENT_IOC_ENABLE)");
      goto error;
    }

  for (int i = 0; i < ev->n_events; i++)
    {
      log_debug ("event %u: %U (%U) hw counter id 0x%x", i,
		 pm->platform->format_event_name, ev->code[i],
		 pm->platform->format_event_details, ev->code[i],
		 perfmon2_calc_pmc_index (pt, i));
    }

error:
  if (err)
    {
      log_err ("%U", format_clib_error, err);
    }
  return err;
}

static void
perfmon2_data_init (vlib_main_t * vm)
{
  perfmon2_main_t *pm = &perfmon2_main;
  uword n_threads = vec_len (vlib_mains);

  vec_validate_aligned (pm->threads, n_threads - 1, CLIB_CACHE_LINE_BYTES);
  for (int i = 0; i < n_threads; i++)
    {
      perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, i);
      for (int j = 0; j < PERF_MAX_EVENTS; j++)
	pt->mmap_pages[j] = MAP_FAILED;
    }
}

static clib_error_t *
perfmon2_init (vlib_main_t * vm)
{
  perfmon2_main_t *pm = &perfmon2_main;
  pm->platform = &perfmon2_platform_intel;
  perfmon2_data_init (vm);

  perfmon2_events_t events = {
    .code[0] = PERF_E_INST_RETIRED_ANY_P,
    .code[1] = PERF_E_CPU_CLK_UNHALTED_THREAD_P,
    .code[2] = PERF_E_CPU_CLK_UNHALTED_REF_TSC,
    .n_events = 3,
  };

  perfmon2_event_start (vm, &events);

  return 0;
  vlib_node_add_pre_dispatch_cb (vm, perfmon2_pre_dispatch_cb);
  vlib_node_add_post_dispatch_cb (vm, perfmon2_post_dispatch_cb);
  return 0;
}

VLIB_INIT_FUNCTION (perfmon2_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
