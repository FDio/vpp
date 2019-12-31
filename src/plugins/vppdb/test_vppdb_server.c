#include <assert.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "vppdb.h"

static
int send_fd(int socket, int fd)
{
  struct msghdr msg = { 0 };
  char buf[CMSG_SPACE(sizeof(fd))];
  memset(buf, '\0', sizeof(buf));
  struct iovec io = { .iov_base = buf, .iov_len = 1 };

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);

  struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

  *((int *) CMSG_DATA(cmsg)) = fd;

  msg.msg_controllen = CMSG_SPACE(sizeof(fd));

  if (sendmsg(socket, &msg, 0) < 0) {
    perror("Failed to send message\n");
    return -1;
  }
  return 0;
}

static void
test_walktree (ds_inode_t *root)
{
  ds_inode_t *d;
  static int level;
  pool_foreach(d, root->directory_vector,
	       ({
		 switch (d->type) {
		 case DS_INODE_TYPE_DIR:
		   printf("%*s%s\n", 2*level, " ", d->name);
		   level++;
		   test_walktree(d);
		   level--;
		   break;
		 case DS_INODE_TYPE_INLINE:
		   printf("%*s%s %lu (inline)\n", 2*level, " ", d->name, d->value);
		   break;
		 case DS_INODE_TYPE_POINTER:
		   printf("%*s%s (pointer)\n", 2*level, " ", d->name);
		   break;
		 default:
		   printf("%*s%s (unknown)\n", 2*level, " ", d->name);
		 }
	       }));
}

static void
test_server (void)
{
  void *memaddr, *heap;
  size_t memory_size = 10000000;
  int mfd;
  int rv = ds_segment_map_init ("test_vppdb", memory_size, &heap, &memaddr, &mfd);
  assert(rv == 0);
  printf("SERVER mfd: %d\n", mfd);

  /* Initialise shared memory header */
  ds_segment_shared_header_t *shared_header = memaddr;
  void *oldheap = clib_mem_set_heap (heap);
  shared_header->version = 123;
  shared_header->base = (intptr_t)memaddr;
  vppdb_init(&shared_header.fs);
  clib_mem_set_heap (oldheap);

  /* Parent */
  printf("PARENT %p\n", memaddr);
  int sock;
  assert((sock = socket (AF_UNIX, SOCK_SEQPACKET, 0)) > 0);
  struct sockaddr_un un = { 0 };
  un.sun_family = AF_UNIX;
  strncpy ((char *) un.sun_path, "\0test_vppdb", sizeof (un.sun_path) - 1);
  assert ((bind (sock, (struct sockaddr *) &un, sizeof (struct sockaddr_un))) == 0);

  assert(listen(sock, 1) >= 0);
  int cl;
  while (1) {
    if ((cl = accept(sock, NULL, NULL)) == -1) {
      perror("accept error");
      continue;
    }
    break;
  }
  send_fd(cl, mfd);
  close(cl);
  close(mfd);

  int i;
  u8 *n = 0;
  int count = 1000;
  printf("ROOT SERVER %p\n", shared_header->root);
  oldheap = clib_mem_set_heap (heap);
  for (i=0; i < count; i++) {
    n = format(0, "/err%d", i);
    assert(ds_mkdir(shared_header->root, (char *)n) == 0);
    vec_reset_length(n);
  }
  vec_free(n);
  clib_mem_set_heap (oldheap);
  printf("Done writing\n");
  test_walktree(shared_header->root);
  sleep(100);
  return;
}

int main (int argc, char **argv)
{
  test_server();
}
