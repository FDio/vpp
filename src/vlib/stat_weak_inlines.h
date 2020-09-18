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
u32 vlib_stats_push_heap (void *) __attribute__ ((weak));

u32
vlib_stats_push_heap (void *unused)
{
  return 0;
};

void vlib_stats_pop_heap (void *, u32, u32, int) __attribute__ ((weak));
void
vlib_stats_pop_heap (void *notused, u32 notused2, u32 i, int type)
{
};
void vlib_stats_register_error_index (u32, u8 *, u64 *, u64)
  __attribute__ ((weak));
void
vlib_stats_register_error_index (u32 notused, u8 * notused2, u64 * notused3, u64 notused4)
{
};

void vlib_stats_pop_heap2 (void *, u32, u32, int) __attribute__ ((weak));
void
vlib_stats_pop_heap2 (void *notused, u32 notused2, u32 notused3,
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
void vlib_stats_delete_cm (void *) __attribute__ ((weak));
void
vlib_stats_delete_cm (void *notused)
{
}

#endif
