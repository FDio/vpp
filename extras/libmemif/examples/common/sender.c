#include <common.h>

int
send_packets (memif_connection_t *c, uint16_t qid,
	      packet_generator_t *generator, uint32_t num_pkts,
	      uint16_t max_pkt_size)
{
  int err, i;
  uint16_t tx;

  do
    {
      err = memif_buffer_alloc (c->conn, qid, c->tx_bufs,
				num_pkts > MAX_MEMIF_BUFS ? MAX_MEMIF_BUFS :
							    num_pkts,
				&c->tx_buf_num, max_pkt_size);
      /* suppress full ring error MEMIF_ERR_NOBUF_RING */
      if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	  goto error;
	}

      /* generate packet inside allocated buffers */
      err = generator (c, num_pkts);
      if (err != 0)
	{
	  INFO ("paclet generator error: %d", err);
	  goto error;
	}

      err = memif_tx_burst (c->conn, qid, c->tx_bufs, c->tx_buf_num, &tx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      c->tx_buf_num -= tx;

      /* Should never happen... */
      if (c->tx_buf_num > 0)
	{
	  INFO ("Failed to send allocated packets");
	  goto error;
	}
      num_pkts -= tx;
    }
  while (num_pkts > 0);

  return 0;

error:
  /* TODO: free alloocated tx buffers */
  return -1;
}