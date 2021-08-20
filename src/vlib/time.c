/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vlib/time.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

static f64
vlib_time_get_next_timer (vlib_main_t *vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  TWT (tw_timer_wheel) *wheel = nm->timing_wheel;
  return TW (tw_timer_first_expires_in_ticks) (wheel) * wheel->timer_interval;
}

void
vlib_time_adjust_global (f64 offset)
{
  foreach_vlib_main ()
    this_vlib_main->time_offset += offset;
}

f64
vlib_time_get_next_timer_global (void)
{
  f64 offset = CLIB_TIME_MAX;
  foreach_vlib_main ()
    offset = clib_min (offset, vlib_time_get_next_timer (this_vlib_main));
  return offset;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
