#include <assert.h>
#include <vppinfra/mem.h>
#include <vppinfra/mheap.h>
#include <vppinfra/socket.h>
#include <vppinfra/file.h>
#undef HAVE_MEMFD_CREATE
#include <vppinfra/linux/syscall.h>

typedef struct {
  clib_socket_t *s;
  int fd;
} ds_socket_t;

int
ds_segment_map_init (char *mem_name, size_t memory_size, void **heap, void **memaddr, int *mfd)
{
  assert(mem_name && memory_size > 0);

  /* Create shared memory segment */
  if ((*mfd = memfd_create (mem_name, 0)) < 0)
    return -1;

  /* Set size */
  if ((ftruncate (*mfd, memory_size)) == -1)
    return -1;

  if ((*memaddr =
       mmap (NULL, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, *mfd,
	     0)) == MAP_FAILED)
    return -1;

#if USE_DLMALLOC == 0
  *heap = mheap_alloc_with_flags (((u8 *) *memaddr) + getpagesize (),
				  memory_size - getpagesize (),
				  MHEAP_FLAG_DISABLE_VM |
				  MHEAP_FLAG_THREAD_SAFE);
#else
  *heap =
    create_mspace_with_base (((u8 *) *memaddr) + getpagesize (),
			     memory_size - getpagesize (), 1 /* locked */ );
  mspace_disable_expand (*heap);
#endif

  return 0;
}

/*
 * Accept connection on the socket and exchange the fd for the shared
 * memory segment.
 */
clib_error_t *
ds_segment_socket_accept_ready (clib_file_t * uf)
{
  clib_error_t *err;
  clib_socket_t client = { 0 };
  ds_socket_t *ds_s = uword_to_pointer(uf->private_data, ds_socket_t *);
  err = clib_socket_accept (ds_s->s, &client);
  if (err)
    {
      clib_error_report (err);
      return err;
    }

  /* Send the fd across and close */
  err = clib_socket_sendmsg (&client, 0, 0, &ds_s->fd, 1);
  if (err)
    clib_error_report (err);
  clib_socket_close (&client);

  return 0;
}
clib_file_main_t file_main;
ds_socket_t *
ds_segment_socket_init (char *socket_name, clib_file_function_t *read_function, int memfd)
{
  clib_socket_t *s = clib_mem_alloc (sizeof (*s));
  ds_socket_t *ds_s = clib_mem_alloc (sizeof (*ds_s));
  memset (s, 0, sizeof (clib_socket_t));
  s->config = socket_name;
  s->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_SEQPACKET |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE | CLIB_SOCKET_F_PASSCRED;

  if (clib_socket_init (s)) {
    clib_mem_free(s);
    clib_mem_free(ds_s);
    return 0;
  }

  ds_s->s = s;
  ds_s->fd = memfd;

  clib_file_t template = { 0 };
  template.read_function = read_function;
  template.file_descriptor = s->fd;
  template.description = format (0, "datastore segment listener %s", s->config);
  template.private_data = pointer_to_uword(ds_s);
  clib_file_add (&file_main, &template);

  return ds_s;
}

void
ds_segment_socket_exit (char *socket_name)
{
  /*
   * cleanup the listener socket on exit.
   */
  unlink (socket_name);
}
