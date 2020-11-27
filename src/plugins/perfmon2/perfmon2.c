/*
 * perfmon.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <perfmon2/perfmon2.h>

perfmon2_main_t perfmon2_main;

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

static void
perfmon2_pre_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);

  switch (pt->n_events)
    {
    case 7:
      pt->pmc_index[6] = pt->mmap_pages[6]->index + pt->mmap_pages[6]->offset;
    case 6:
      pt->pmc_index[5] = pt->mmap_pages[5]->index + pt->mmap_pages[5]->offset;
    case 5:
      pt->pmc_index[4] = pt->mmap_pages[4]->index + pt->mmap_pages[4]->offset;
    case 4:
      pt->pmc_index[3] = pt->mmap_pages[3]->index + pt->mmap_pages[3]->offset;
    case 3:
      pt->pmc_index[2] = pt->mmap_pages[2]->index + pt->mmap_pages[2]->offset;
    case 2:
      pt->pmc_index[1] = pt->mmap_pages[1]->index + pt->mmap_pages[1]->offset;
    case 1:
      pt->pmc_index[0] = pt->mmap_pages[0]->index + pt->mmap_pages[0]->offset;
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
  perfmon2_read_pmcs (pt, pt->node_pre_counters);
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
      pt->group_fd = -1;
    }
}

static clib_error_t *
perfmon2_init (vlib_main_t * vm)
{
  perfmon2_data_init (vm);
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
