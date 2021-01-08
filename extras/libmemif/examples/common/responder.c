#include <unistd.h>
#include <pthread.h>

#include <common.h>

int
responder (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  memif_connection_t *c = (memif_connection_t *) private_ctx;
  int err, i;
  uint16_t tx;

  /* receive packets from the shared memory */
  err = memif_rx_burst (conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &c->rx_buf_num);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_rx_burst: %s", memif_strerror (err));
      return err;
    }

  do
    {
      /* allocate tx buffers */
      err = memif_buffer_alloc (conn, qid, c->tx_bufs, c->rx_buf_num,
				&c->tx_buf_num, 2048);
      /* suppress full ring error MEMIF_ERR_NOBUF_RING */
      if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_alloc: %s", memif_strerror (err));
	  goto error;
	}

      /* Process the packets */
      if (c->packet_handler == NULL)
	{
	  INFO ("Missing packet handler");
	  goto error;
	}
      err = c->packet_handler (c);
      if (err != 0)
	{
	  INFO ("packet handler error: %d", err);
	  goto error;
	}
      /* Done processing packets */

      /* refill the queue */
      err = memif_refill_queue (conn, qid, c->tx_buf_num, 0);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_refill_queue: %s", memif_strerror (err));
	  goto error;
	}
      c->rx_buf_num -= c->tx_buf_num;

      err = memif_tx_burst (conn, qid, c->tx_bufs, c->tx_buf_num, &tx);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      c->tx_buf_num -= tx;

      /* This should never happen */
      if (c->tx_buf_num != 0)
	{
	  INFO ("memif_tx_burst failed to send all allocated buffers.");
	  goto error;
	}
    }
  while (c->rx_buf_num > 0);

  return 0;

error:
  err = memif_refill_queue (conn, qid, c->rx_buf_num, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_refill_queue: %s", memif_strerror (err));
      return err;
    }
  c->rx_buf_num = 0;

  return -1;
}

int
responder_zero_copy (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  memif_connection_t *c = (memif_connection_t *) private_ctx;
  int err, i;
  uint16_t tx, tx2;

  /* receive packets from the shared memory */
  err = memif_rx_burst (conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &c->rx_buf_num);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_rx_burst: %s", memif_strerror (err));
      return err;
    }

  do
    {
      /* Note that in zero copy memif_buffer_alloc is not part of respond
      process,
       * instead rx buffers are used directly using memif_buffer_enq_tx.
       * /

      /* Process the packets */
      if (c->packet_handler == NULL)
	{
	  INFO ("Missing packet handler");
	  goto error;
	}
      err = c->packet_handler (c);
      if (err != 0)
	{
	  INFO ("packet handler error: %d", err);
	  goto error;
	}
      /* Done processing packets */

      /* Swap rx and tx buffers, swapped tx buffers are considered allocated
       * and are ready to be transmitted. Notice that the buffers are swapped
       * only in memif driver and locally remain in rx_bufs queue.
       */
      err = memif_buffer_enq_tx (conn, qid, c->rx_bufs, c->rx_buf_num, &tx);
      /* suppress full ring error MEMIF_ERR_NOBUF_RING */
      if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_enq_tx: %s", memif_strerror (err));
	  goto error;
	}

      /* refill the queue */
      err = memif_refill_queue (conn, qid, tx, 0);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_refill_queue: %s", memif_strerror (err));
	  goto error;
	}
      c->rx_buf_num -= tx;

      /* Notice that we send from rx_bufs as the buffers were only swapped
       * internally in memif driver */
      err = memif_tx_burst (conn, qid, c->rx_bufs, tx, &tx2);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      tx -= tx2;

      /* This should never happen */
      if (tx != 0)
	{
	  INFO ("memif_tx_burst failed to send all allocated buffers.");
	  goto error;
	}
    }
  while (c->rx_buf_num > 0);

  return 0;

error:
  err = memif_refill_queue (conn, qid, c->rx_buf_num, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_refill_queue: %s", memif_strerror (err));
      return err;
    }
  c->rx_buf_num = 0;

  return -1;
}

void *
reply_with_delay(void *data)
{
  memif_connection_t *c = (memif_connection_t *) data;
  uint16_t tx = 0;
  int err;

  sleep(2);

  err = memif_buffer_enq_tx (c->conn, 0, c->rx_bufs, 1, &tx);
  if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_enq_tx: %s", memif_strerror (err));
	  return NULL;
	}

  err = memif_tx_burst(c->conn, 0, c->rx_bufs, tx, &tx);
  if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  return NULL;
	}

  return NULL;
}

int
responder_zero_copy_out_of_order (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  memif_connection_t *c = (memif_connection_t *) private_ctx;
  int err, i;
  uint16_t tx0, tx1, tx2;
  pthread_t thread_id;

  /* receive packets from the shared memory */
  err = memif_rx_burst (conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &c->rx_buf_num);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_rx_burst: %s", memif_strerror (err));
      return err;
    }

  do
    {
      /* Process the packets */
      if (c->packet_handler == NULL)
	{
	  INFO ("Missing packet handler");
	  goto error;
	}
      err = c->packet_handler (c);
      if (err != 0)
	{
	  INFO ("packet handler error: %d", err);
	  goto error;
	}
      /* Done processing packets */

      /* frst buffer will be `held for processing` on tx queue 1 */
      err = memif_buffer_enq_tx (conn, 1, c->rx_bufs, 1, &tx1);
      if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_enq_tx: %s", memif_strerror (err));
	  goto error;
	}
  pthread_create(&thread_id, NULL, reply_with_delay, c);

      /* Remaining buffers are enqueued to primary queue */
      err = memif_buffer_enq_tx (conn, qid, c->rx_bufs + 1, c->rx_buf_num - tx1, &tx0);
      /* suppress full ring error MEMIF_ERR_NOBUF_RING */
      if (err != MEMIF_ERR_SUCCESS && err != MEMIF_ERR_NOBUF_RING)
	{
	  INFO ("memif_buffer_enq_tx: %s", memif_strerror (err));
	  goto error;
	}

      /* refill all buffers on rx queue */
      err = memif_refill_queue (conn, qid, tx0 + tx1, 0);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_refill_queue: %s", memif_strerror (err));
	  goto error;
	}
      c->rx_buf_num -= tx0 + tx1;

      /* Notice that we send from rx_bufs as the buffers were only swapped
       * internally in memif driver */
      err = memif_tx_burst (conn, qid, c->rx_bufs + 1, tx0, &tx2);
      if (err != MEMIF_ERR_SUCCESS)
	{
	  INFO ("memif_tx_burst: %s", memif_strerror (err));
	  goto error;
	}
      tx0 -= tx2;

      /* This should never happen */
      if (tx0 != 0)
	{
	  INFO ("memif_tx_burst failed to send all allocated buffers.");
	  goto error;
	}
    }
  while (c->rx_buf_num > 0);

  pthread_join(thread_id, NULL);

  return 0;

error:
  err = memif_refill_queue (conn, qid, c->rx_buf_num, 0);
  if (err != MEMIF_ERR_SUCCESS)
    {
      INFO ("memif_refill_queue: %s", memif_strerror (err));
      return err;
    }
  c->rx_buf_num = 0;

  return -1;
}