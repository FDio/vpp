/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/test/test.h>
#include <vppinfra/vec.h>

static clib_error_t *
test_vec_foreach_pointer_empty (clib_error_t *err)
{
  u32 log2_page_size = clib_mem_get_log2_page_size ();
  uword page_size = 1ULL << log2_page_size;
  void *map;
  uword **v;
  uword n = 0;

  map = clib_mem_vm_map (0, 2 * page_size, log2_page_size, "test");
  if (map == CLIB_MEM_VM_MAP_FAILED)
    return clib_error_return (err, "clib_mem_vm_map failed");

  v = map + page_size;
  clib_memset (_vec_find (v), 0, sizeof (vec_header_t));

  if (mprotect (v, page_size, PROT_NONE) != 0)
    {
      err = clib_error_return_unix (err, "mprotect failed");
      goto done;
    }

  vec_foreach_pointer (p, v)
    n++;

  if (n != 0)
    err = clib_error_return (err, "iterated over an empty vector");

done:
  clib_mem_vm_unmap (map);
  return err;
}

REGISTER_TEST (vec_foreach_pointer_empty) = {
  .name = "vec_foreach_pointer_empty",
  .fn = test_vec_foreach_pointer_empty,
};
