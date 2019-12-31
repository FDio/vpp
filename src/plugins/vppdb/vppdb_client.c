#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "vppdb_hash.h"
#include "vppdb_client.h"
#include "vppdb_inlines.h"

static inline void
stat_segment_access_start (stat_segment_access_t * sa,
			   stat_client_main_t * sm)
{
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  sa->epoch = shared_header->epoch;
  while (shared_header->in_progress != 0)
    ;
  sm->directory_vector = (stat_segment_directory_entry_t *)
    stat_segment_pointer (sm->shared_header,
			  sm->shared_header->directory_offset);
}

static inline bool
stat_segment_access_end (stat_segment_access_t * sa, stat_client_main_t * sm)
{
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  if (shared_header->epoch != sa->epoch || shared_header->in_progress)
    return false;
  return true;
}


static int
recv_fd (int sock)
{
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  int fd = -1;
  char iobuf[1];
  struct iovec io = {.iov_base = iobuf,.iov_len = sizeof (iobuf) };
  union
  {
    char buf[CMSG_SPACE (sizeof (fd))];
    struct cmsghdr align;
  } u;
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof (u.buf);

  ssize_t size;
  if ((size = recvmsg (sock, &msg, 0)) < 0)
    {
      perror ("recvmsg failed");
      return -1;
    }
  cmsg = CMSG_FIRSTHDR (&msg);
  if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
    {
      memmove (&fd, CMSG_DATA (cmsg), sizeof (fd));
    }
  return fd;
}

/*
 * Map shared memory from socket name
 */
int
ds_client_map_init (const char *socket_name, void **memaddr, size_t *memory_size)
{
  int mfd = -1;
  int sock;

  if ((sock = socket (AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
    {
      perror ("Stat client couldn't open socket");
      return -1;
    }

  struct sockaddr_un un = { 0 };
  un.sun_family = AF_UNIX;
  strncpy ((char *) un.sun_path, socket_name, sizeof (un.sun_path) - 1);
  if (connect (sock, (struct sockaddr *) &un, sizeof (struct sockaddr_un)) <
      0)
    {
      close (sock);
      return -2;
    }

  if ((mfd = recv_fd (sock)) < 0) {
    close (sock);
    fprintf (stderr, "Receiving file descriptor failed\n");
    return -3;
  }
  close (sock);

  /* mmap shared memory segment. */
  struct stat st = { 0 };

  if (fstat (mfd, &st) == -1) {
    perror ("mmap fstat failed");
    return -1;
  }
  if ((*memaddr = mmap (0, st.st_size, PROT_READ, MAP_SHARED, mfd, 0)) == MAP_FAILED) {
    perror ("mmap map failed");
    return -2;
  }
  
  *memory_size = st.st_size;
  return 0;
}

intptr_t shared_memory_offset;

void
ds_set_offset(intptr_t offset)
{
  shared_memory_offset = offset;
}
intptr_t
ds_get_offset(void)
{
  return shared_memory_offset;
}

void
assert_pointer(void *p)
{
  ds_main_t *dsm = &ds_main;
  if (p) {
    assert(p >= dsm->base && p <= (dsm->base + dsm->memory_size));
  }
}

/*
 * Given a pointer in the shared memory segment, adjust for this
 * process' mapping in the virtual address space.
 *
 */
void *
ds_pointer_adjust (void *pointer)
{
  if (!pointer) return 0;

  //verify that pointer is valid

  return (void *)(intptr_t)pointer + ds_get_offset();
}

hash_pair_t *vppdb_lookup (void *v, uword key);

int
ds_client_lookup(ds_inode_t *root, const char *pathname, ds_inode_t **r)
{
  hash_pair_t *hp;
  int i;

  assert(root);
  assert(pathname);
  root = ds_pointer_adjust(root);
  ds_inode_t *dir = root;

  /* Split path into individual elements */
  char **paths = split_path(pathname);
  uint64_t epoch = root->epoch;
  vec_foreach_index(i, paths) {
    if (root->in_progress || root->epoch != epoch) return -3;
    hp = vppdb_lookup (dir->directory_vector_by_name, pointer_to_uword(paths[i]));
    if (!hp) {
      return -1;
    }
    if (root->in_progress || root->epoch != epoch) return -4;
    ds_inode_t *ds = ds_pointer_adjust(dir->directory_vector);
    dir = &ds[hp->value[0]];
    if (dir->type != DS_INODE_TYPE_DIR) {
      if (i != vec_len(paths) - 1) {
	return -1;
      }
      break;
    }
  }

  split_path_free(paths);
  *r = dir;
  return 0;
}
