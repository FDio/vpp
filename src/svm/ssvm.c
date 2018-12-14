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
#include <svm/ssvm.h>
#include <svm/svm_common.h>

typedef int (*init_fn) (ssvm_private_t *);
typedef void (*delete_fn) (ssvm_private_t *);

static init_fn master_init_fns[SSVM_N_SEGMENT_TYPES] =
  { ssvm_master_init_shm, ssvm_master_init_memfd, ssvm_master_init_private };
static init_fn slave_init_fns[SSVM_N_SEGMENT_TYPES] =
  { ssvm_slave_init_shm, ssvm_slave_init_memfd, ssvm_slave_init_private };
static delete_fn delete_fns[SSVM_N_SEGMENT_TYPES] =
  { ssvm_delete_shm, ssvm_delete_memfd, ssvm_delete_private };

int
ssvm_master_init_shm (ssvm_private_t * ssvm)
{
  int ssvm_fd;
#if USE_DLMALLOC == 0
  int mh_flags = MHEAP_FLAG_DISABLE_VM | MHEAP_FLAG_THREAD_SAFE;
#endif
  clib_mem_vm_map_t mapa = { 0 };
  u8 junk = 0, *ssvm_filename;
  ssvm_shared_header_t *sh;
  uword page_size, requested_va = 0;
  void *oldheap;

  if (ssvm->ssvm_size == 0)
    return SSVM_API_ERROR_NO_SIZE;

  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] creating segment '%s'", getpid (), ssvm->name);

  ASSERT (vec_c_string_is_terminated (ssvm->name));
  ssvm_filename = format (0, "/dev/shm/%s%c", ssvm->name, 0);
  unlink ((char *) ssvm_filename);
  vec_free (ssvm_filename);

  ssvm_fd = shm_open ((char *) ssvm->name, O_RDWR | O_CREAT | O_EXCL, 0777);
  if (ssvm_fd < 0)
    {
      clib_unix_warning ("create segment '%s'", ssvm->name);
      return SSVM_API_ERROR_CREATE_FAILURE;
    }

  if (fchmod (ssvm_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0)
    clib_unix_warning ("ssvm segment chmod");
  if (svm_get_root_rp ())
    {
      /* TODO: is this really needed? */
      svm_main_region_t *smr = svm_get_root_rp ()->data_base;
      if (fchown (ssvm_fd, smr->uid, smr->gid) < 0)
	clib_unix_warning ("ssvm segment chown");
    }

  if (lseek (ssvm_fd, ssvm->ssvm_size, SEEK_SET) < 0)
    {
      clib_unix_warning ("lseek");
      close (ssvm_fd);
      return SSVM_API_ERROR_SET_SIZE;
    }

  if (write (ssvm_fd, &junk, 1) != 1)
    {
      clib_unix_warning ("set ssvm size");
      close (ssvm_fd);
      return SSVM_API_ERROR_SET_SIZE;
    }

  page_size = clib_mem_get_fd_page_size (ssvm_fd);
  if (ssvm->requested_va)
    {
      requested_va = ssvm->requested_va;
      clib_mem_vm_randomize_va (&requested_va, min_log2 (page_size));
    }

  mapa.requested_va = requested_va;
  mapa.size = ssvm->ssvm_size;
  mapa.fd = ssvm_fd;
  if (clib_mem_vm_ext_map (&mapa))
    {
      clib_unix_warning ("mmap");
      close (ssvm_fd);
      return SSVM_API_ERROR_MMAP;
    }
  close (ssvm_fd);

  sh = mapa.addr;
  sh->master_pid = ssvm->my_pid;
  sh->ssvm_size = ssvm->ssvm_size;
  sh->ssvm_va = pointer_to_uword (sh);
  sh->type = SSVM_SEGMENT_SHM;
#if USE_DLMALLOC == 0
  sh->heap = mheap_alloc_with_flags (((u8 *) sh) + page_size,
				     ssvm->ssvm_size - page_size, mh_flags);
#else
  sh->heap = create_mspace_with_base (((u8 *) sh) + page_size,
				      ssvm->ssvm_size - page_size,
				      1 /* locked */ );
  mspace_disable_expand (sh->heap);
#endif

  oldheap = ssvm_push_heap (sh);
  sh->name = format (0, "%s", ssvm->name, 0);
  ssvm_pop_heap (oldheap);

  ssvm->sh = sh;
  ssvm->my_pid = getpid ();
  ssvm->i_am_master = 1;

  /* The application has to set set sh->ready... */
  return 0;
}

int
ssvm_slave_init_shm (ssvm_private_t * ssvm)
{
  struct stat stat;
  int ssvm_fd = -1;
  ssvm_shared_header_t *sh;

  ASSERT (vec_c_string_is_terminated (ssvm->name));
  ssvm->i_am_master = 0;

  while (ssvm->attach_timeout-- > 0)
    {
      if (ssvm_fd < 0)
	ssvm_fd = shm_open ((char *) ssvm->name, O_RDWR, 0777);
      if (ssvm_fd < 0)
	{
	  sleep (1);
	  continue;
	}
      if (fstat (ssvm_fd, &stat) < 0)
	{
	  sleep (1);
	  continue;
	}

      if (stat.st_size > 0)
	goto map_it;
    }
  clib_warning ("slave timeout");
  return SSVM_API_ERROR_SLAVE_TIMEOUT;

map_it:
  sh = (void *) mmap (0, MMAP_PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		      ssvm_fd, 0);
  if (sh == MAP_FAILED)
    {
      clib_unix_warning ("slave research mmap");
      close (ssvm_fd);
      return SSVM_API_ERROR_MMAP;
    }

  while (ssvm->attach_timeout-- > 0)
    {
      if (sh->ready)
	goto re_map_it;
    }
  close (ssvm_fd);
  munmap (sh, MMAP_PAGESIZE);
  clib_warning ("slave timeout 2");
  return SSVM_API_ERROR_SLAVE_TIMEOUT;

re_map_it:
  ssvm->requested_va = sh->ssvm_va;
  ssvm->ssvm_size = sh->ssvm_size;
  munmap (sh, MMAP_PAGESIZE);

  sh = ssvm->sh = (void *) mmap ((void *) ssvm->requested_va, ssvm->ssvm_size,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_FIXED, ssvm_fd, 0);

  if (sh == MAP_FAILED)
    {
      clib_unix_warning ("slave final mmap");
      close (ssvm_fd);
      return SSVM_API_ERROR_MMAP;
    }
  sh->slave_pid = getpid ();
  return 0;
}

void
ssvm_delete_shm (ssvm_private_t * ssvm)
{
  u8 *fn;

  fn = format (0, "/dev/shm/%s%c", ssvm->name, 0);

  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] unlinking ssvm (%s) backing file '%s'", getpid (),
		  ssvm->name, fn);

  /* Throw away the backing file */
  if (unlink ((char *) fn) < 0)
    clib_unix_warning ("unlink segment '%s'", ssvm->name);

  vec_free (fn);
  vec_free (ssvm->name);

  munmap ((void *) ssvm->requested_va, ssvm->ssvm_size);
}

/**
 * Initialize memfd segment master
 */
int
ssvm_master_init_memfd (ssvm_private_t * memfd)
{
  uword page_size;
  ssvm_shared_header_t *sh;
  void *oldheap;
  clib_mem_vm_alloc_t alloc = { 0 };
  clib_error_t *err;

  if (memfd->ssvm_size == 0)
    return SSVM_API_ERROR_NO_SIZE;

  ASSERT (vec_c_string_is_terminated (memfd->name));

  alloc.name = (char *) memfd->name;
  alloc.size = memfd->ssvm_size;
  alloc.flags = CLIB_MEM_VM_F_SHARED;
  alloc.requested_va = memfd->requested_va;
  if ((err = clib_mem_vm_ext_alloc (&alloc)))
    {
      clib_error_report (err);
      return SSVM_API_ERROR_CREATE_FAILURE;
    }

  memfd->fd = alloc.fd;
  memfd->sh = (ssvm_shared_header_t *) alloc.addr;
  memfd->my_pid = getpid ();
  memfd->i_am_master = 1;

  page_size = 1ull << alloc.log2_page_size;
  sh = memfd->sh;
  sh->master_pid = memfd->my_pid;
  sh->ssvm_size = memfd->ssvm_size;
  sh->ssvm_va = pointer_to_uword (sh);
  sh->type = SSVM_SEGMENT_MEMFD;

#if USE_DLMALLOC == 0
  uword flags = MHEAP_FLAG_DISABLE_VM | MHEAP_FLAG_THREAD_SAFE;

  sh->heap = mheap_alloc_with_flags (((u8 *) sh) + page_size,
				     memfd->ssvm_size - page_size, flags);
#else
  sh->heap = create_mspace_with_base (((u8 *) sh) + page_size,
				      memfd->ssvm_size - page_size,
				      1 /* locked */ );
  mspace_disable_expand (sh->heap);
#endif
  oldheap = ssvm_push_heap (sh);
  sh->name = format (0, "%s", memfd->name, 0);
  ssvm_pop_heap (oldheap);

  /* The application has to set set sh->ready... */
  return 0;
}

/**
 * Initialize memfd segment slave
 *
 * Subtly different than svm_slave_init. The caller needs to acquire
 * a usable file descriptor for the memfd segment e.g. via
 * vppinfra/socket.c:default_socket_recvmsg
 */
int
ssvm_slave_init_memfd (ssvm_private_t * memfd)
{
  clib_mem_vm_map_t mapa = { 0 };
  ssvm_shared_header_t *sh;
  uword page_size;

  memfd->i_am_master = 0;

  page_size = clib_mem_get_fd_page_size (memfd->fd);
  if (!page_size)
    {
      clib_unix_warning ("page size unknown");
      return SSVM_API_ERROR_MMAP;
    }

  /*
   * Map the segment once, to look at the shared header
   */
  mapa.fd = memfd->fd;
  mapa.size = page_size;

  if (clib_mem_vm_ext_map (&mapa))
    {
      clib_unix_warning ("slave research mmap (fd %d)", mapa.fd);
      close (memfd->fd);
      return SSVM_API_ERROR_MMAP;
    }

  sh = mapa.addr;
  memfd->requested_va = sh->ssvm_va;
  memfd->ssvm_size = sh->ssvm_size;
  clib_mem_vm_free (sh, page_size);

  /*
   * Remap the segment at the 'right' address
   */
  mapa.requested_va = memfd->requested_va;
  mapa.size = memfd->ssvm_size;
  if (clib_mem_vm_ext_map (&mapa))
    {
      clib_unix_warning ("slave final mmap");
      close (memfd->fd);
      return SSVM_API_ERROR_MMAP;
    }

  sh = mapa.addr;
  sh->slave_pid = getpid ();
  memfd->sh = sh;
  return 0;
}

void
ssvm_delete_memfd (ssvm_private_t * memfd)
{
  vec_free (memfd->name);
  clib_mem_vm_free (memfd->sh, memfd->ssvm_size);
  close (memfd->fd);
}

/**
 * Initialize segment in a private heap
 */
int
ssvm_master_init_private (ssvm_private_t * ssvm)
{
  ssvm_shared_header_t *sh;
  u32 pagesize = clib_mem_get_page_size ();
  u32 rnd_size = 0;
  u8 *heap;

  rnd_size = (ssvm->ssvm_size + (pagesize - 1)) & ~(pagesize - 1);
  rnd_size = clib_min (rnd_size, ((u64) 1 << 32) - pagesize);

#if USE_DLMALLOC == 0
  {
    mheap_t *heap_header;

    heap = mheap_alloc (0, rnd_size);
    if (heap == 0)
      {
	clib_unix_warning ("mheap alloc");
	return -1;
      }
    heap_header = mheap_header (heap);
    heap_header->flags |= MHEAP_FLAG_THREAD_SAFE;
  }
#else
  heap = create_mspace (rnd_size, 1 /* locked */ );
#endif

  ssvm->ssvm_size = rnd_size;
  ssvm->i_am_master = 1;
  ssvm->my_pid = getpid ();
  ssvm->requested_va = ~0;

  /* Allocate a [sic] shared memory header, in process memory... */
  sh = clib_mem_alloc_aligned (sizeof (*sh), CLIB_CACHE_LINE_BYTES);
  ssvm->sh = sh;

  clib_memset (sh, 0, sizeof (*sh));
  sh->heap = heap;
  sh->type = SSVM_SEGMENT_PRIVATE;

  return 0;
}

int
ssvm_slave_init_private (ssvm_private_t * ssvm)
{
  clib_warning ("BUG: this should not be called!");
  return -1;
}

void
ssvm_delete_private (ssvm_private_t * ssvm)
{
  vec_free (ssvm->name);
#if USE_DLMALLOC == 0
  mheap_free (ssvm->sh->heap);
#else
  destroy_mspace (ssvm->sh->heap);
#endif
  clib_mem_free (ssvm->sh);
}

int
ssvm_master_init (ssvm_private_t * ssvm, ssvm_segment_type_t type)
{
  return (master_init_fns[type]) (ssvm);
}

int
ssvm_slave_init (ssvm_private_t * ssvm, ssvm_segment_type_t type)
{
  return (slave_init_fns[type]) (ssvm);
}

void
ssvm_delete (ssvm_private_t * ssvm)
{
  delete_fns[ssvm->sh->type] (ssvm);
}

ssvm_segment_type_t
ssvm_type (const ssvm_private_t * ssvm)
{
  return ssvm->sh->type;
}

u8 *
ssvm_name (const ssvm_private_t * ssvm)
{
  return ssvm->sh->name;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
