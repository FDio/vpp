#include <vppinfra/socket.h>
#include <vppinfra/bihash_16_8_32.h>

#include <vppinfra/bihash_template.c>

int
test0 (int is_add, int nitems)
{
  clib_socket_t s = { 0 };
  clib_error_t *err;
  int memfd;
  BVT (clib_bihash) hash, *h;
  BVT (clib_bihash_kv) kv;
  int i;

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
	   h->alloc_arena, h->sh->alloc_arena_size);

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
  return 0;
}

int
test1 (int nitems)
{
  BVT (clib_bihash) hash1, hash2, *h1, *h2;
  BVT (clib_bihash_kv) kv;
  int i;

  /* Make two hashes in this address space */
  h1 = &hash1;
  memset (h1, 0, sizeof (*h1));
  h2 = &hash2;
  memset (h2, 0, sizeof (*h2));

  /* Master init once */
  BV (clib_bihash_master_init_svm) (h1, "test1", 1 /* nbuckets */ ,
				    64 << 20);
  /* Slave init, same table, second place */
  BV (clib_bihash_slave_init_svm) (h2, "test2", h1->memfd);

  /* Add through the first mapping */
  for (i = 0; i < nitems; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = i + 201;

      BV (clib_bihash_add_del) (h1, &kv, 1 /* is_add */ );
    }

  if (0)
    {
      fformat (stdout, "Initial table...\n");
      fformat (stdout, "%U", BV (format_bihash), h2, 1 /* verbose */ );
    }

  fformat (stdout, "Search second map for %d KVPs...\n", nitems);
  /* Search through the second mapping */
  for (i = 0; i < nitems; i++)
    {
      int rv;
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = 0;

      rv = BV (clib_bihash_search) (h2, &kv, &kv);

      if (rv != 0)
	fformat (stdout, "add: key %d not found\n", i);

      if (kv.value != (i + 201))
	fformat (stdout, "key %d value %lld not %d\n", kv.value, i + 201);
    }

  /* delete half the items through the second mapping */
  fformat (stdout, "Delete %d items through second map...\n", nitems / 2);
  for (i = 0; i < nitems / 2; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = i + 201;

      BV (clib_bihash_add_del) (h2, &kv, 0 /* is_add */ );
    }

  fformat (stdout, "Search first map for %d KVPs...\n", nitems / 2);
  /* Search through the second mapping */
  for (; i < nitems; i++)
    {
      int rv;
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = 0;

      rv = BV (clib_bihash_search) (h1, &kv, &kv);

      if (rv != 0)
	fformat (stdout, "add: key %d not found\n", i);

      if (kv.value != (i + 201))
	fformat (stdout, "key %d value %lld not %d\n", kv.value, i + 201);
    }

  /* delete half the items through the second mapping */
  fformat (stdout, "Delete %d items through first map...\n",
	   nitems - nitems / 2);
  for (i = nitems / 2; i < nitems; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = i + 201;

      BV (clib_bihash_add_del) (h1, &kv, 0 /* is_add */ );
    }

  fformat (stdout, "Delete the first table...\n");
  BV (clib_bihash_free) (h1);

  fformat (stdout, "Final table through the second map...\n");
  fformat (stdout, "%U", BV (format_bihash), h2, 1 /* verbose */ );

  fformat (stdout, "Delete the second table...\n");


  return 0;
}


int
main (int argc, char **argv)
{
  int is_add = 1;
  int test_id = 0;
  int nitems;
  int rv;
  unformat_input_t _input, *input = &_input;

  memset (input, 0, sizeof (*input));

  clib_mem_init (0, 128 << 20);

  unformat_init_command_line (input, argv);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delete %d", &nitems))
	is_add = 0;
      else if (unformat (input, "add %d", &nitems))
	is_add = 1;
      else if (unformat (input, "double-map %d", &nitems))
	test_id = 1;
      else
	{
	  fformat (stderr, "usage: [add | delete] <nitems>\n");
	  exit (1);
	}
    }

  switch (test_id)
    {
    case 0:
      rv = test0 (is_add, nitems);
      break;
    case 1:
      rv = test1 (nitems);
    }

  exit (rv);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
