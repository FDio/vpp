/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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


/*
 * Test the allocator sanity by repeatedly calling vec_add1() within
 * a custom small-ish heap. As of today (nov 20 2018), the behavior
 * when called via "test allocator" is that it continues to expand
 * the vector until some random (relatively large) length, which
 * may differ from run to run, and then whatever the allocator
 * returns fails the test of being the heap object.
 *
 * Calling the "test allocator disable-expand" fails consistently
 * at a much smaller vector length with the crash reason being
 * "out of memory" - as expected.
 */


typedef struct
{
  u8 meat[48];
  u8 fat[16];
} chunk_of_bacon_t;


static clib_error_t *
test_allocator_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  void *my_heap = mheap_alloc_with_lock (0 /* use VM */ , 32 * 1024 * 1024,
					 1 /* locked */ );
  if (unformat (input, "disable-expand")) {
     mspace_disable_expand(my_heap);
  }
  void *oldheap = clib_mem_set_heap (my_heap);
  chunk_of_bacon_t *vec_bacon = 0;

  /* this is bound to exceed the capacity of the mheap */

  while (vec_len (vec_bacon) < 1000000)
    {
      /* *INDENT-OFF* */
      chunk_of_bacon_t new_bacon = {.meat = {0xff}, .fat = {0xaa} };
      /* *INDENT-ON* */
      vec_add1 (vec_bacon, new_bacon);
      if (!(vec_len (vec_bacon) % 10000))
	{
	  vlib_cli_output (vm, "survived the vector size of %d elements",
			   vec_len (vec_bacon));
	}
      ASSERT (clib_mem_is_heap_object (vec_bacon));
    }
  /* never gets reached.... */
  clib_mem_set_heap (oldheap);

  /* Not so much... */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_crash_command, static) =
{
  .path = "test allocator",
  .short_help = "demonstrate the (in)sanity of memory allocator (crashes the box)",
  .function = test_allocator_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
