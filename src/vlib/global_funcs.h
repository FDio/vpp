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
/*
 * global_funcs.h: global data structure access functions
 */

#ifndef included_vlib_global_funcs_h_
#define included_vlib_global_funcs_h_

always_inline u32
vlib_get_n_threads ()
{
  return vec_len (vlib_global_main.vlib_mains);
}

always_inline vlib_main_t *
vlib_get_main_by_index (clib_thread_index_t thread_index)
{
  vlib_main_t *vm;
  vm = vlib_global_main.vlib_mains[thread_index];
  ASSERT (vm);
  return vm;
}

always_inline vlib_main_t *
vlib_get_main (void)
{
  return vlib_get_main_by_index (vlib_get_thread_index ());
}

always_inline vlib_main_t *
vlib_get_first_main (void)
{
  return vlib_get_main_by_index (0);
}

always_inline vlib_global_main_t *
vlib_get_global_main (void)
{
  return &vlib_global_main;
}

always_inline vlib_thread_main_t *
vlib_get_thread_main ()
{
  return &vlib_thread_main;
}

always_inline elog_main_t *
vlib_get_elog_main ()
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  return &vgm->elog_main;
}

#endif /* included_vlib_global_funcs_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
