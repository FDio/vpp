/*
 *------------------------------------------------------------------
 * svmtool.c
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>

#include "svm.h"



/*
 * format_all_svm_regions
 * Maps / unmaps regions. Do NOT call from client code!
 */
u8 *
format_all_svm_regions (u8 * s, va_list * args)
{
  int verbose = va_arg (*args, int);
  svm_region_t *root_rp = svm_get_root_rp ();
  svm_main_region_t *mp;
  svm_subregion_t *subp;
  svm_region_t *rp;
  svm_map_region_args_t *a = 0;
  u8 **svm_names = 0;
  u8 *name = 0;
  int i;

  ASSERT (root_rp);

  pthread_mutex_lock (&root_rp->mutex);

  s = format (s, "%U", format_svm_region, root_rp, verbose);

  mp = root_rp->data_base;

  /*
   * Snapshoot names, can't hold root rp mutex across
   * find_or_create.
   */
  /* *INDENT-OFF* */
  pool_foreach (subp, mp->subregions, ({
        name = vec_dup (subp->subregion_name);
        vec_add1(svm_names, name);
      }));
  /* *INDENT-ON* */

  pthread_mutex_unlock (&root_rp->mutex);

  for (i = 0; i < vec_len (svm_names); i++)
    {
      vec_validate (a, 0);
      a->name = (char *) svm_names[i];
      rp = svm_region_find_or_create (a);
      if (rp)
	{
	  pthread_mutex_lock (&rp->mutex);
	  s = format (s, "%U", format_svm_region, rp, verbose);
	  pthread_mutex_unlock (&rp->mutex);
	  svm_region_unmap (rp);
	  vec_free (svm_names[i]);
	}
      vec_free (a);
    }
  vec_free (svm_names);
  return (s);
}

void
show (char *chroot_path, int verbose)
{
  svm_map_region_args_t *a = 0;

  vec_validate (a, 0);

  svm_region_init_chroot (chroot_path);

  fformat (stdout, "My pid is %d\n", getpid ());

  fformat (stdout, "%U", format_all_svm_regions, verbose);

  svm_region_exit ();

  vec_free (a);
}


static void *
svm_map_region_nolock (svm_map_region_args_t * a)
{
  int svm_fd;
  svm_region_t *rp;
  int deadman = 0;
  u8 *shm_name;

  ASSERT ((a->size & ~(MMAP_PAGESIZE - 1)) == a->size);

  shm_name = shm_name_from_svm_map_region_args (a);

  svm_fd = shm_open ((char *) shm_name, O_RDWR, 0777);

  if (svm_fd < 0)
    {
      perror ("svm_region_map(mmap open)");
      return (0);
    }
  vec_free (shm_name);

  rp = mmap (0, MMAP_PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED, svm_fd, 0);

  if (rp == (svm_region_t *) MAP_FAILED)
    {
      close (svm_fd);
      clib_warning ("mmap");
      return (0);
    }
  /*
   * We lost the footrace to create this region; make sure
   * the winner has crossed the finish line.
   */
  while (rp->version == 0 && deadman++ < 5)
    {
      sleep (1);
    }

  /*
   * <bleep>-ed?
   */
  if (rp->version == 0)
    {
      clib_warning ("rp->version %d not %d", rp->version, SVM_VERSION);
      munmap (rp, MMAP_PAGESIZE);
      return (0);
    }
  /* Remap now that the region has been placed */
  a->baseva = rp->virtual_base;
  a->size = rp->virtual_size;
  munmap (rp, MMAP_PAGESIZE);

  rp = (void *) mmap (uword_to_pointer (a->baseva, void *), a->size,
		      PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_FIXED, svm_fd, 0);
  if ((uword) rp == (uword) MAP_FAILED)
    {
      clib_unix_warning ("mmap");
      return (0);
    }

  if ((uword) rp != rp->virtual_base)
    {
      clib_warning ("mmap botch");
    }

  if (pthread_mutex_trylock (&rp->mutex))
    {
      clib_warning ("rp->mutex LOCKED by pid %d, tag %d, cleared...",
		    rp->mutex_owner_pid, rp->mutex_owner_tag);
      clib_memset (&rp->mutex, 0, sizeof (rp->mutex));

    }
  else
    {
      clib_warning ("mutex OK...\n");
      pthread_mutex_unlock (&rp->mutex);
    }

  return ((void *) rp);
}

/*
 * rnd_pagesize
 * Round to a pagesize multiple, presumably 4k works
 */
static u64
rnd_pagesize (u64 size)
{
  u64 rv;

  rv = (size + (MMAP_PAGESIZE - 1)) & ~(MMAP_PAGESIZE - 1);
  return (rv);
}

#define MUTEX_DEBUG

always_inline void
region_lock (svm_region_t * rp, int tag)
{
  pthread_mutex_lock (&rp->mutex);
#ifdef MUTEX_DEBUG
  rp->mutex_owner_pid = getpid ();
  rp->mutex_owner_tag = tag;
#endif
}

always_inline void
region_unlock (svm_region_t * rp)
{
#ifdef MUTEX_DEBUG
  rp->mutex_owner_pid = 0;
  rp->mutex_owner_tag = 0;
#endif
  pthread_mutex_unlock (&rp->mutex);
}


static void *
svm_existing_region_map_nolock (void *root_arg, svm_map_region_args_t * a)
{
  svm_region_t *root_rp = root_arg;
  svm_main_region_t *mp;
  svm_region_t *rp;
  void *oldheap;
  uword *p;

  a->size += MMAP_PAGESIZE +
    (a->pvt_heap_size ? a->pvt_heap_size : SVM_PVT_MHEAP_SIZE);
  a->size = rnd_pagesize (a->size);

  region_lock (root_rp, 4);
  oldheap = svm_push_pvt_heap (root_rp);
  mp = root_rp->data_base;

  ASSERT (mp);

  p = hash_get_mem (mp->name_hash, a->name);

  if (p)
    {
      rp = svm_map_region_nolock (a);
      region_unlock (root_rp);
      svm_pop_heap (oldheap);
      return rp;
    }
  return 0;

}

static void
trace (char *chroot_path, char *name, int enable_disable)
{
  svm_map_region_args_t *a = 0;
  svm_region_t *db_rp;
  void *oldheap;

  vec_validate (a, 0);

  svm_region_init_chroot (chroot_path);

  a->name = name;
  a->size = 1 << 20;
  a->flags = SVM_FLAGS_MHEAP;

  db_rp = svm_region_find_or_create (a);

  ASSERT (db_rp);

  region_lock (db_rp, 20);

  oldheap = svm_push_data_heap (db_rp);

  mheap_trace (db_rp->data_heap, enable_disable);

  svm_pop_heap (oldheap);
  region_unlock (db_rp);

  svm_region_unmap ((void *) db_rp);
  svm_region_exit ();
  vec_free (a);
}



static void
subregion_repair (char *chroot_path)
{
  int i;
  svm_main_region_t *mp;
  svm_map_region_args_t a;
  svm_region_t *root_rp;
  svm_region_t *rp;
  svm_subregion_t *subp;
  u8 *name = 0;
  u8 **svm_names = 0;

  svm_region_init_chroot (chroot_path);
  root_rp = svm_get_root_rp ();

  pthread_mutex_lock (&root_rp->mutex);

  mp = root_rp->data_base;

  /*
   * Snapshoot names, can't hold root rp mutex across
   * find_or_create.
   */
  /* *INDENT-OFF* */
  pool_foreach (subp, mp->subregions, ({
        name = vec_dup (subp->subregion_name);
        vec_add1(svm_names, name);
      }));
  /* *INDENT-ON* */

  pthread_mutex_unlock (&root_rp->mutex);

  for (i = 0; i < vec_len (svm_names); i++)
    {
      clib_memset (&a, 0, sizeof (a));
      a.root_path = chroot_path;
      a.name = (char *) svm_names[i];
      fformat (stdout, "Checking %s region...\n", a.name);
      rp = svm_existing_region_map_nolock (root_rp, &a);
      if (rp)
	{
	  svm_region_unmap (rp);
	  vec_free (svm_names[i]);
	}
    }
  vec_free (svm_names);
}

void
repair (char *chroot_path, int crash_root_region)
{
  svm_region_t *root_rp = 0;
  svm_map_region_args_t *a = 0;
  void *svm_map_region (svm_map_region_args_t * a);
  int svm_fd;
  u8 *shm_name;

  fformat (stdout, "our pid: %d\n", getpid ());

  vec_validate (a, 0);

  a->root_path = chroot_path;
  a->name = SVM_GLOBAL_REGION_NAME;
  a->baseva = svm_get_global_region_base_va ();
  a->size = SVM_GLOBAL_REGION_SIZE;
  a->flags = SVM_FLAGS_NODATA;

  shm_name = shm_name_from_svm_map_region_args (a);

  svm_fd = shm_open ((char *) shm_name, O_RDWR, 0777);

  if (svm_fd < 0)
    {
      perror ("svm_region_map(mmap open)");
      goto out;
    }

  vec_free (shm_name);

  root_rp = mmap (0, MMAP_PAGESIZE,
		  PROT_READ | PROT_WRITE, MAP_SHARED, svm_fd, 0);

  if (root_rp == (svm_region_t *) MAP_FAILED)
    {
      close (svm_fd);
      clib_warning ("mmap");
      goto out;
    }

  /* Remap now that the region has been placed */
  clib_warning ("remap to 0x%x", root_rp->virtual_base);

  a->baseva = root_rp->virtual_base;
  a->size = root_rp->virtual_size;
  munmap (root_rp, MMAP_PAGESIZE);

  root_rp = (void *) mmap (uword_to_pointer (a->baseva, void *), a->size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_FIXED, svm_fd, 0);
  if ((uword) root_rp == (uword) MAP_FAILED)
    {
      clib_unix_warning ("mmap");
      goto out;
    }

  close (svm_fd);

  if ((uword) root_rp != root_rp->virtual_base)
    {
      clib_warning ("mmap botch");
      goto out;
    }

  if (pthread_mutex_trylock (&root_rp->mutex))
    {
      clib_warning ("root_rp->mutex LOCKED by pid %d, tag %d, cleared...",
		    root_rp->mutex_owner_pid, root_rp->mutex_owner_tag);
      clib_memset (&root_rp->mutex, 0, sizeof (root_rp->mutex));
      goto out;
    }
  else
    {
      clib_warning ("root_rp->mutex OK...\n");
      pthread_mutex_unlock (&root_rp->mutex);
    }

out:
  vec_free (a);
  /*
   * Now that the root region is known to be OK,
   * fix broken subregions
   */
  subregion_repair (chroot_path);

  if (crash_root_region)
    {
      clib_warning ("Leaving root region locked on purpose...");
      pthread_mutex_lock (&root_rp->mutex);
      root_rp->mutex_owner_pid = getpid ();
      root_rp->mutex_owner_tag = 99;
    }
  svm_region_exit ();
}

int
main (int argc, char **argv)
{
  unformat_input_t input;
  int parsed = 0;
  char *name;
  char *chroot_path = 0;
  u8 *chroot_u8;

  unformat_init_command_line (&input, argv);

  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "show-verbose"))
	{
	  show (chroot_path, 1);
	  parsed++;
	}
      else if (unformat (&input, "show"))
	{
	  show (chroot_path, 0);
	  parsed++;
	}
      else if (unformat (&input, "client-scan"))
	{
	  svm_client_scan (chroot_path);
	  parsed++;
	}
      else if (unformat (&input, "repair"))
	{
	  repair (chroot_path, 0 /* fix it */ );
	  parsed++;
	}
      else if (unformat (&input, "crash"))
	{
	  repair (chroot_path, 1 /* crash it */ );
	  parsed++;
	}
      else if (unformat (&input, "trace-on %s", &name))
	{
	  trace (chroot_path, name, 1);
	  parsed++;
	}
      else if (unformat (&input, "trace-off %s", &name))
	{
	  trace (chroot_path, name, 0);
	  parsed++;
	}
      else if (unformat (&input, "chroot %s", &chroot_u8))
	{
	  chroot_path = (char *) chroot_u8;
	}
      else
	{
	  break;
	}
    }

  unformat_free (&input);

  if (!parsed)
    {
      fformat (stdout,
	       "%s: show | show-verbose | client-scan | trace-on <region-name>\n",
	       argv[0]);
      fformat (stdout, "      trace-off <region-name>\n");
    }
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
