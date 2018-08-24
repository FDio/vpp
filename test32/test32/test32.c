#include <vppinfra/socket.h>
#include <vppinfra/bihash_16_8_32.h>

#include <vppinfra/bihash_template.c>

int
main (int argc, char **argv)
{
  clib_socket_t s = { 0 };
  clib_error_t *err;
  int memfd;
  BVT(clib_bihash) hash, *h;
  BVT (clib_bihash_kv) kv;
  int i;

  clib_mem_init (0, 128 << 20);

  s.config = "/tmp/bi32.sock";
  s.flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;
  err = clib_socket_init (&s);
  if (err)
    {
      clib_error_report (err);
      exit (1);
    }
  err = clib_socket_recvmsg (&s, 0, 0, &memfd, 1);
  if (err)
    {
      clib_error_report (err);
      return -1;
    }
  clib_socket_close (&s);

  ASSERT (memfd);

  h = &hash;
  memset(h, 0, sizeof (*h));

  BV (clib_bihash_init_svm) (h, "test", 0 /* nbuckets */,
			     0 /* base_addr from shmem hdr */ ,
			     0 /* memory size from shmem hdr */, 
                             memfd /* slave memfd */ );

  fformat (stdout, "Table mapped at 0x%llx, size %lld, go add 100 KVPs...\n",
           h->sh->alloc_arena, h->sh->alloc_arena_size);

  for (i = 0; i < 100; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = i + 201;

      BV (clib_bihash_add_del) (h, &kv, 1 /* is_add */ );
    }

  fformat (stdout, "Search for 100 KVPs...\n");
  for (i = 0; i < 100; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = 0;

      BV (clib_bihash_search) (h, &kv, &kv);

      if (kv.value != (i + 201))
          fformat (stdout, "key %d value %lld not %d\n", kv.value, i+201);
    }
  fformat (stdout, "Final table...\n");
  fformat (stdout, "%U", BV(format_bihash), h, 1 /* verbose */);
  exit (0);
}
