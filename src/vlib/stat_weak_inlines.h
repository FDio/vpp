/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

/*
 * NOTE: Only include this file from external components that require
 * a loose coupling to the stats component.
 */

#ifndef included_stat_weak_inlines_h
#define included_stat_weak_inlines_h
void *vlib_stats_push_heap (void *) __attribute__ ((weak));
void *
vlib_stats_push_heap (void *unused)
{
  return 0;
};

void vlib_stats_pop_heap (void *, void *, u32, int) __attribute__ ((weak));
void
vlib_stats_pop_heap (void *notused, void *notused2, u32 i, int type)
{
};
void vlib_stats_register_error_index (void *, u8 *, u64 *, u64)
  __attribute__ ((weak));
void
vlib_stats_register_error_index (void * notused, u8 * notused2, u64 * notused3, u64 notused4)
{
};

void vlib_stats_pop_heap2 (void *, u32, void *, int) __attribute__ ((weak));
void
vlib_stats_pop_heap2 (void *notused, u32 notused2, void *notused3,
		      int notused4)
{
};

void vlib_stat_segment_lock (void) __attribute__ ((weak));
void
vlib_stat_segment_lock (void)
{
}

void vlib_stat_segment_unlock (void) __attribute__ ((weak));
void
vlib_stat_segment_unlock (void)
{
}

#endif
