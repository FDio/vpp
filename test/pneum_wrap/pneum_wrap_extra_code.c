/* this file is never compiled standalone, only added to the pneum.c
   to provide additional code when building the C extension */

int pneum_get_map (int table_size, unsigned long *values, const char **keys)
{
  hash_pair_t *hp;
  uword *h = pneum_msg_table_get_hash ();

  u32 counter = 0;
  hash_foreach_pair (hp, h, ({
                       if (counter > table_size)
                         {
                           return -1;
                         }
                       values[counter] = (unsigned long)hp->value[0];
                       keys[counter] = (char *)hp->key;
                       counter++;
                     }));
  return 0;
}

static void global_msg_handler (char *data, int len);
static void global_async_msg_handler (char *data, int len);

int wrap_pneum_connect (char *name, char *chroot_prefix)
{
  return pneum_connect (name, chroot_prefix,
                        (void (*) (unsigned char *, int))global_msg_handler);
}

int wrap_pneum_connect_async (char *name, char *chroot_prefix)
{
  return pneum_connect (
      name, chroot_prefix,
      (void (*) (unsigned char *, int))global_async_msg_handler);
}
