#include <vppinfra/socket.h>
#include <vppinfra/bihash_16_8_32.h>

#include <vppinfra/bihash_template.c>

int
main (int argc, char **argv)
{
  clib_socket_t s = { 0 };
  clib_error_t *err;
  int memfd;
  BVT (clib_bihash) hash, *h;
  BVT (clib_bihash_kv) kv;
  int i, nitems;
  int is_add = 1;
  unformat_input_t _input, *input = &_input;

  memset (input, 0, sizeof (*input));

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
  memset (h, 0, sizeof (*h));

  BV (clib_bihash_slave_init_svm) (h, "test", memfd);

  fformat (stdout, "Table mapped at 0x%llx, size %lld...\n",
	   h->sh->alloc_arena, h->sh->alloc_arena_size);

  unformat_init_command_line (input, argv);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delete %d", &nitems))
	is_add = 0;
      else if (unformat (input, "add %d", &nitems))
	is_add = 1;
      else
	{
	  fformat (stderr, "usage: [add | delete] <nitems>\n");
	  exit (1);
	}
    }

  for (i = 0; i < nitems; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = i + 201;

      BV (clib_bihash_add_del) (h, &kv, is_add);
    }

  fformat (stdout, "Search for %d KVPs...\n", nitems);
  for (i = 0; i < nitems; i++)
    {
      int rv;
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = 0;

      rv = BV (clib_bihash_search) (h, &kv, &kv);

      if (is_add && rv != 0)
	fformat (stdout, "add: key %d not found\n", i);

      if (is_add && kv.value != (i + 201))
	fformat (stdout, "key %d value %lld not %d\n", kv.value, i + 201);

      if (is_add == 0 && rv == 0)
	fformat (stdout, "del: key %d found but it was just deleted\n", i);
    }
  fformat (stdout, "Final table...\n");
  fformat (stdout, "%U", BV (format_bihash), h, 1 /* verbose */ );
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
