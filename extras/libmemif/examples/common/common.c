#include <common.h>

void
print_memif_ring_details (memif_connection_t *c, uint16_t qid, uint8_t is_rx)
{
  /* TODO: print memif shared memory details */
}

void
print_memif_rx_ring_details (memif_connection_t *c, uint16_t qid)
{
  print_memif_ring_details (c, qid, /* RX */ 1);
}

void
print_memif_tx_ring_details (memif_connection_t *c, uint16_t qid)
{
  print_memif_ring_details (c, qid, /* TX */ 0);
}

void
print_version ()
{
  printf ("libmemif version: %s, memif version: %s\n", LIBMEMIF_VERSION,
	  memif_get_version_str ());
}

int
parse_ip4 (const char *input, uint8_t out[4])
{
  char *ui, *end;
  char *tmp = strdup (input);

  ui = strtok (tmp, ".");
  if (ui == NULL)
    return -1;
  out[0] = strtol (ui, &end, 10);

  ui = strtok (NULL, ".");
  if (ui == NULL)
    return -1;
  out[1] = strtol (ui, &end, 10);

  ui = strtok (NULL, ".");
  if (ui == NULL)
    return -1;
  out[2] = strtol (ui, &end, 10);

  ui = strtok (NULL, ".");
  if (ui == NULL)
    return -1;
  out[3] = strtol (ui, &end, 10);

  free (tmp);

  return 0;
}

int
parse_mac (const char *input, uint8_t out[6])
{
  char *ui, *end;
  char *tmp = strdup (input);

  ui = strtok (tmp, ":");
  if (ui == NULL)
    return -1;
  out[0] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    return -1;
  out[1] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    return -1;
  out[2] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    return -1;
  out[3] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    return -1;
  out[4] = strtol (ui, &end, 16);
  ui = strtok (NULL, ":");
  if (ui == NULL)
    return -1;
  out[5] = strtol (ui, &end, 16);

  free (tmp);

  return 0;
}

void
alloc_memif_buffers (memif_connection_t *c)
{
  c->rx_bufs =
    (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  c->rx_buf_num = 0;
  c->tx_bufs =
    (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
  c->tx_buf_num = 0;
}

void
free_memif_buffers (memif_connection_t *c)
{
  if (c->rx_bufs != NULL)
    free (c->rx_bufs);
  c->rx_bufs = NULL;
  c->rx_buf_num = 0;
  if (c->tx_bufs != NULL)
    free (c->tx_bufs);
  c->tx_bufs = NULL;
  c->tx_buf_num = 0;
}

void
print_memif_details (memif_connection_t *c)
{
  printf ("MEMIF DETAILS\n");
  printf ("==============================\n");

  memif_details_t md;
  memset (&md, 0, sizeof (md));
  ssize_t buflen = 2048;
  char *buf = (char *) malloc (buflen);
  memset (buf, 0, buflen);
  int err, e;

  err = memif_get_details (c->conn, &md, buf, buflen);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("%s", memif_strerror (err));
      if (err == MEMIF_ERR_NOCONN)
	{
	  free (buf);
	  return;
	}
    }

  printf ("\tinterface name: %s\n", (char *) md.if_name);
  printf ("\tapp name: %s\n", (char *) md.inst_name);
  printf ("\tremote interface name: %s\n", (char *) md.remote_if_name);
  printf ("\tremote app name: %s\n", (char *) md.remote_inst_name);
  printf ("\tid: %u\n", md.id);
  printf ("\tsecret: %s\n", (char *) md.secret);
  printf ("\trole: ");
  if (md.role)
    printf ("slave\n");
  else
    printf ("master\n");
  printf ("\tmode: ");
  switch (md.mode)
    {
    case 0:
      printf ("ethernet\n");
      break;
    case 1:
      printf ("ip\n");
      break;
    case 2:
      printf ("punt/inject\n");
      break;
    default:
      printf ("unknown\n");
      break;
    }
  printf ("\tsocket path: %s\n", (char *) md.socket_path);
  printf ("\trx queues:\n");
  for (e = 0; e < md.rx_queues_num; e++)
    {
      printf ("\t\tqueue id: %u\n", md.rx_queues[e].qid);
      printf ("\t\tring size: %u\n", md.rx_queues[e].ring_size);
      printf ("\t\tbuffer size: %u\n", md.rx_queues[e].buffer_size);
    }
  printf ("\ttx queues:\n");
  for (e = 0; e < md.tx_queues_num; e++)
    {
      printf ("\t\tqueue id: %u\n", md.tx_queues[e].qid);
      printf ("\t\tring size: %u\n", md.tx_queues[e].ring_size);
      printf ("\t\tbuffer size: %u\n", md.tx_queues[e].buffer_size);
    }
  printf ("\tlink: ");
  if (md.link_up_down)
    printf ("up\n");
  else
    printf ("down\n");

  free (buf);
}
