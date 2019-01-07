/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <main_test.h>

#include <memif_private.h>

#define SOCKET_FILENAME "/run/vpp/memif.sock"

uint8_t ready_called;
#define read_call  (1 << 0)
#define write_call (1 << 1)
#define error_call (1 << 2)

int
read_fn (memif_connection_t * c)
{
  ready_called |= read_call;
  return 0;
}

int
write_fn (memif_connection_t * c)
{
  ready_called |= write_call;
  return 0;
}

int
error_fn (memif_connection_t * c)
{
  ready_called |= error_call;
  return 0;
}

static void
register_fd_ready_fn (memif_connection_t * c,
		      memif_fn * read_fn, memif_fn * write_fn,
		      memif_fn * error_fn)
{
  c->read_fn = read_fn;
  c->write_fn = write_fn;
  c->error_fn = error_fn;
}

START_TEST (test_init)
{
  int err;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  libmemif_main_t *lm = &libmemif_main;

  ck_assert_ptr_ne (lm, NULL);
  ck_assert_ptr_ne (lm->control_fd_update, NULL);
  ck_assert_int_gt (lm->timerfd, 2);

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;
}

END_TEST
START_TEST (test_init_epoll)
{
  int err;

  if ((err =
       memif_init (NULL, TEST_APP_NAME, NULL, NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  libmemif_main_t *lm = &libmemif_main;

  ck_assert_ptr_ne (lm, NULL);
  ck_assert_ptr_ne (lm->control_fd_update, NULL);
  ck_assert_int_gt (lm->timerfd, 2);
  ck_assert_int_gt (memif_epfd, -1);

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;
}

END_TEST
START_TEST (test_create)
{
  int err;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  ck_assert_ptr_ne (c, NULL);

  ck_assert_uint_eq (c->args.interface_id, args.interface_id);
  ck_assert_uint_eq (c->args.is_master, args.is_master);
  ck_assert_uint_eq (c->args.mode, args.mode);

  ck_assert_uint_eq (c->args.num_s2m_rings, MEMIF_DEFAULT_TX_QUEUES);
  ck_assert_uint_eq (c->args.num_m2s_rings, MEMIF_DEFAULT_RX_QUEUES);
  ck_assert_uint_eq (c->args.buffer_size, MEMIF_DEFAULT_BUFFER_SIZE);
  ck_assert_uint_eq (c->args.log2_ring_size, MEMIF_DEFAULT_LOG2_RING_SIZE);

  ck_assert_ptr_eq (c->msg_queue, NULL);
  ck_assert_ptr_eq (c->regions, NULL);
  ck_assert_ptr_eq (c->tx_queues, NULL);
  ck_assert_ptr_eq (c->rx_queues, NULL);

  ck_assert_int_eq (c->fd, -1);

  ck_assert_ptr_ne (c->on_connect, NULL);
  ck_assert_ptr_ne (c->on_disconnect, NULL);
  ck_assert_ptr_ne (c->on_interrupt, NULL);

  ck_assert_str_eq ((char *)c->args.interface_name, (char *)args.interface_name);
  ck_assert_str_eq ((char *)c->args.socket_filename, SOCKET_FILENAME);

  struct itimerspec timer;
  timerfd_gettime (lm->timerfd, &timer);

  ck_assert_msg (timer.it_interval.tv_sec == lm->arm.it_interval.tv_sec,
		 "timerfd not armed!");

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_create_master)
{
  int err, rv;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.is_master = 1;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  ck_assert_ptr_ne (c, NULL);

  ck_assert_uint_eq (c->args.interface_id, args.interface_id);
  ck_assert_uint_eq (c->args.is_master, args.is_master);
  ck_assert_uint_eq (c->args.mode, args.mode);

  ck_assert_uint_eq (c->args.num_s2m_rings, MEMIF_DEFAULT_TX_QUEUES);
  ck_assert_uint_eq (c->args.num_m2s_rings, MEMIF_DEFAULT_RX_QUEUES);
  ck_assert_uint_eq (c->args.buffer_size, MEMIF_DEFAULT_BUFFER_SIZE);
  ck_assert_uint_eq (c->args.log2_ring_size, MEMIF_DEFAULT_LOG2_RING_SIZE);

  ck_assert_ptr_eq (c->msg_queue, NULL);
  ck_assert_ptr_eq (c->regions, NULL);
  ck_assert_ptr_eq (c->tx_queues, NULL);
  ck_assert_ptr_eq (c->rx_queues, NULL);

  ck_assert_int_eq (c->fd, -1);

  ck_assert_ptr_ne (c->on_connect, NULL);
  ck_assert_ptr_ne (c->on_disconnect, NULL);
  ck_assert_ptr_ne (c->on_interrupt, NULL);

  ck_assert_str_eq ((char *)c->args.interface_name, (char *)args.interface_name);
  ck_assert_str_eq ((char *)c->args.socket_filename, SOCKET_FILENAME);

  struct stat file_stat;

  rv = stat (SOCKET_FILENAME, &file_stat);
  ck_assert_int_eq (rv, 0);

  ck_assert (S_ISSOCK (file_stat.st_mode));

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_create_mult)
{
  int err;
  memif_conn_handle_t conn = NULL;
  memif_conn_handle_t conn1 = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  args.interface_id = 1;

  if ((err = memif_create (&conn1, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;
  memif_connection_t *c1 = (memif_connection_t *) conn1;

  ck_assert_ptr_ne (c, NULL);
  ck_assert_ptr_ne (c1, NULL);

  ck_assert_uint_eq (c->args.interface_id, 0);
  ck_assert_uint_eq (c->args.is_master, args.is_master);
  ck_assert_uint_eq (c->args.mode, args.mode);
  ck_assert_uint_eq (c1->args.interface_id, 1);
  ck_assert_uint_eq (c1->args.is_master, args.is_master);
  ck_assert_uint_eq (c1->args.mode, args.mode);

  ck_assert_uint_eq (c->args.num_s2m_rings, MEMIF_DEFAULT_TX_QUEUES);
  ck_assert_uint_eq (c->args.num_m2s_rings, MEMIF_DEFAULT_RX_QUEUES);
  ck_assert_uint_eq (c->args.buffer_size, MEMIF_DEFAULT_BUFFER_SIZE);
  ck_assert_uint_eq (c->args.log2_ring_size, MEMIF_DEFAULT_LOG2_RING_SIZE);
  ck_assert_uint_eq (c1->args.num_s2m_rings, MEMIF_DEFAULT_TX_QUEUES);
  ck_assert_uint_eq (c1->args.num_m2s_rings, MEMIF_DEFAULT_RX_QUEUES);
  ck_assert_uint_eq (c1->args.buffer_size, MEMIF_DEFAULT_BUFFER_SIZE);
  ck_assert_uint_eq (c1->args.log2_ring_size, MEMIF_DEFAULT_LOG2_RING_SIZE);

  ck_assert_ptr_eq (c->msg_queue, NULL);
  ck_assert_ptr_eq (c->regions, NULL);
  ck_assert_ptr_eq (c->tx_queues, NULL);
  ck_assert_ptr_eq (c->rx_queues, NULL);
  ck_assert_ptr_eq (c1->msg_queue, NULL);
  ck_assert_ptr_eq (c1->regions, NULL);
  ck_assert_ptr_eq (c1->tx_queues, NULL);
  ck_assert_ptr_eq (c1->rx_queues, NULL);

  ck_assert_int_eq (c->fd, -1);
  ck_assert_int_eq (c1->fd, -1);

  ck_assert_ptr_ne (c->on_connect, NULL);
  ck_assert_ptr_ne (c->on_disconnect, NULL);
  ck_assert_ptr_ne (c->on_interrupt, NULL);
  ck_assert_ptr_ne (c1->on_connect, NULL);
  ck_assert_ptr_ne (c1->on_disconnect, NULL);
  ck_assert_ptr_ne (c1->on_interrupt, NULL);

  ck_assert_str_eq ((char *)c->args.interface_name, (char *)args.interface_name);
  ck_assert_str_eq ((char *)c->args.socket_filename, SOCKET_FILENAME);
  ck_assert_str_eq ((char *)c1->args.interface_name, (char *)args.interface_name);
  ck_assert_str_eq ((char *)c1->args.socket_filename, SOCKET_FILENAME);

  struct itimerspec timer;
  timerfd_gettime (lm->timerfd, &timer);

  ck_assert_msg (timer.it_interval.tv_sec == lm->arm.it_interval.tv_sec,
		 "timerfd not armed!");

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_control_fd_handler)
{
  int err;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  if ((err =
       memif_control_fd_handler (lm->timerfd,
				 MEMIF_FD_EVENT_READ)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_NO_FILE, "err code: %u, err msg: %s", err,
		   memif_strerror (err));

  register_fd_ready_fn (c, read_fn, write_fn, error_fn);
  c->fd = 69;
  lm->control_list[0].key = c->fd;
  lm->control_list[0].data_struct = c;

  if ((err =
       memif_control_fd_handler (c->fd,
				 MEMIF_FD_EVENT_READ)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert (ready_called & read_call);

  if ((err =
       memif_control_fd_handler (c->fd,
				 MEMIF_FD_EVENT_WRITE)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert (ready_called & write_call);

  if ((err =
       memif_control_fd_handler (c->fd,
				 MEMIF_FD_EVENT_ERROR)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert (ready_called & error_call);

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_buffer_alloc)
{
  int err, i;
  uint8_t qid;
  uint16_t buf;
  memif_buffer_t *bufs;
  uint16_t max_buf = 10;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  c->fd = 69;

  /* test buffer allocation qid 0 (positive) */

  bufs = malloc (sizeof (memif_buffer_t) * max_buf);

  qid = 0;
  if ((err =
       memif_buffer_alloc (conn, qid, bufs, max_buf,
			   &buf,
			   MEMIF_DEFAULT_BUFFER_SIZE)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (buf, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_uint_eq (bufs[i].len, MEMIF_DEFAULT_BUFFER_SIZE);

  /* test buffer allocation qid 1 (positive) */
  free (bufs);
  bufs = malloc (sizeof (memif_buffer_t) * max_buf);

  qid = 1;
  if ((err =
       memif_buffer_alloc (conn, qid, bufs, max_buf,
			   &buf,
			   MEMIF_DEFAULT_BUFFER_SIZE)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (buf, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_uint_eq (bufs[i].len, MEMIF_DEFAULT_BUFFER_SIZE);

  /* test buffer allocation qid 2 (negative) */

  free (bufs);
  bufs = malloc (sizeof (memif_buffer_t) * max_buf);

  qid = 2;
  if ((err =
       memif_buffer_alloc (conn, qid, bufs, max_buf,
			   &buf,
			   MEMIF_DEFAULT_BUFFER_SIZE)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_QID, "err code: %u, err msg: %s", err,
		   memif_strerror (err));

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  free (bufs);
  bufs = NULL;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_tx_burst)
{
  int err, i;
  uint16_t max_buf = 10, buf, tx;
  uint8_t qid;
  memif_buffer_t *bufs;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  c->fd = 69;

  /* test transmit qid 0 (positive) */

  bufs = malloc (sizeof (memif_buffer_t) * max_buf);
  qid = 0;
  if ((err =
       memif_buffer_alloc (conn, qid, bufs, max_buf,
			   &buf,
			   MEMIF_DEFAULT_BUFFER_SIZE)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (buf, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_uint_eq (bufs[i].len, MEMIF_DEFAULT_BUFFER_SIZE);

  if ((err =
       memif_tx_burst (conn, qid, bufs, max_buf, &tx)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (tx, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_ptr_eq (bufs[i].data, NULL);

  /* test transmit qid 1 (positive) */
  free (bufs);
  bufs = malloc (sizeof (memif_buffer_t) * max_buf);
  qid = 1;
  if ((err =
       memif_buffer_alloc (conn, qid, bufs, max_buf,
			   &buf,
			   MEMIF_DEFAULT_BUFFER_SIZE)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (buf, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_uint_eq (bufs[i].len, MEMIF_DEFAULT_BUFFER_SIZE);

  if ((err =
       memif_tx_burst (conn, qid, bufs, max_buf, &tx)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (tx, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_ptr_eq (bufs[i].data, NULL);

  /* test transmit qid 2 (negative) */
  free (bufs);
  bufs = malloc (sizeof (memif_buffer_t) * max_buf);
  qid = 2;
  if ((err =
       memif_tx_burst (conn, qid, bufs, max_buf, &tx)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_QID, "err code: %u, err msg: %s", err,
		   memif_strerror (err));

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;
  free (bufs);
  bufs = NULL;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_rx_burst)
{
  int err, i;
  uint16_t max_buf = 10, buf, rx;
  uint8_t qid;
  memif_buffer_t *bufs;
  memif_queue_t *mq;
  memif_ring_t *ring;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  c->fd = 69;

  /* test receive qid 0 (positive) */
  qid = 0;
  mq = &c->rx_queues[qid];
  ring = mq->ring;
  ring->tail += max_buf;

  bufs = malloc (sizeof (memif_buffer_t) * max_buf);

  if ((err =
       memif_rx_burst (conn, qid, bufs, max_buf, &rx)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (rx, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_ptr_ne (bufs[i].data, NULL);

  /* test receive qid 1 (positive) */
  qid = 1;
  mq = &c->rx_queues[qid];
  ring = mq->ring;
  ring->tail += max_buf;

  free (bufs);
  bufs = malloc (sizeof (memif_buffer_t) * max_buf);

  if ((err =
       memif_rx_burst (conn, qid, bufs, max_buf, &rx)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (rx, max_buf);
  for (i = 0; i < max_buf; i++)
    ck_assert_ptr_ne (bufs[i].data, NULL);

  /* test receive qid 2 (negative) */
  free (bufs);
  bufs = malloc (sizeof (memif_buffer_t) * max_buf);

  if ((err =
       memif_rx_burst (conn, qid, bufs, max_buf, &rx)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_QID, "err code: %u, err msg: %s", err,
		   memif_strerror (err));

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;
  free (bufs);
  bufs = NULL;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_get_details)
{
  int err, i;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_details_t md;
  memset (&md, 0, sizeof (md));
  ssize_t buflen = 2048;
  char *buf = malloc (buflen);
  memset (buf, 0, buflen);

  if ((err = memif_get_details (conn, &md, buf, buflen)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_str_eq ((char *)md.if_name, (char *)c->args.interface_name);
  ck_assert_str_eq ((char *)md.remote_if_name, (char *)c->remote_if_name);
  ck_assert_str_eq ((char *)md.remote_inst_name, (char *)c->remote_name);
  ck_assert_str_eq ((char *)md.secret, (char *)c->args.secret);
  ck_assert_str_eq ((char *)md.socket_filename, (char *)c->args.socket_filename);

  ck_assert_uint_eq (md.id, c->args.interface_id);
  ck_assert_uint_ne (md.role, c->args.is_master);
  ck_assert_uint_eq (md.mode, c->args.mode);
  for (i = 0; i < md.rx_queues_num; i++)
    {
      ck_assert_uint_eq (md.rx_queues[i].qid, i);
      ck_assert_uint_eq (md.rx_queues[i].ring_size,
			 (1 << c->args.log2_ring_size));
      ck_assert_uint_eq (md.rx_queues[i].buffer_size, c->args.buffer_size);
    }
  for (i = 0; i < md.tx_queues_num; i++)
    {
      ck_assert_uint_eq (md.tx_queues[i].qid, i);
      ck_assert_uint_eq (md.tx_queues[i].ring_size,
			 (1 << c->args.log2_ring_size));
      ck_assert_uint_eq (md.tx_queues[i].buffer_size, c->args.buffer_size);
    }
  ck_assert_uint_eq (md.link_up_down, 0);

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_init_regions_and_queues)
{
  int err;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_ptr_ne (c->regions, NULL);
  ck_assert_ptr_ne (c->tx_queues, NULL);
  ck_assert_ptr_ne (c->rx_queues, NULL);

  ck_assert_ptr_ne (c->regions->addr, NULL);
  ck_assert_ptr_ne (c->tx_queues->ring, NULL);
  ck_assert_ptr_ne (c->rx_queues->ring, NULL);

  ck_assert_int_ne (c->regions->fd, -1);
  ck_assert_uint_eq (c->tx_queues->ring->cookie, MEMIF_COOKIE);
  ck_assert_uint_eq (c->rx_queues->ring->cookie, MEMIF_COOKIE);

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_connect1)
{
  int err;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if ((err = memif_connect1 (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST
START_TEST (test_disconnect_internal)
{
  int err;
  ready_called = 0;
  memif_conn_handle_t conn = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));
  args.num_s2m_rings = 2;
  args.num_m2s_rings = 2;

  libmemif_main_t *lm = &libmemif_main;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  strncpy ((char *) args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_create (&conn, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *c = (memif_connection_t *) conn;

  c->run_args.num_s2m_rings = 2;
  c->run_args.num_m2s_rings = 2;
  c->run_args.log2_ring_size = 10;
  c->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if ((err = memif_disconnect_internal (c)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_int_eq (c->fd, -1);

  ck_assert_ptr_eq (c->tx_queues, NULL);
  ck_assert_ptr_eq (c->rx_queues, NULL);
  ck_assert_ptr_eq (c->regions, NULL);
  ck_assert_ptr_eq (c->msg_queue, NULL);

  struct itimerspec timer;
  timerfd_gettime (lm->timerfd, &timer);

  ck_assert_msg (timer.it_interval.tv_sec == lm->arm.it_interval.tv_sec,
		 "timerfd not armed!");

  if (lm->timerfd > 0)
    close (lm->timerfd);
  lm->timerfd = -1;

  memif_delete (&conn);
  ck_assert_ptr_eq (conn, NULL);
}

END_TEST Suite *
main_suite ()
{
  Suite *s;

  TCase *tc_api;
  TCase *tc_internal;

  /* create main test suite */
  s = suite_create ("Libmemif main");

  /* create api test case */
  tc_api = tcase_create ("Api calls");
  /* add tests to test case */
  tcase_add_test (tc_api, test_init);
  tcase_add_test (tc_api, test_init_epoll);
  tcase_add_test (tc_api, test_create);
  tcase_add_test (tc_api, test_create_master);
  tcase_add_test (tc_api, test_create_mult);
  tcase_add_test (tc_api, test_control_fd_handler);
  tcase_add_test (tc_api, test_buffer_alloc);
  tcase_add_test (tc_api, test_tx_burst);
  tcase_add_test (tc_api, test_rx_burst);
  tcase_add_test (tc_api, test_get_details);

  /* create internal test case */
  tc_internal = tcase_create ("Internal");
  /* add tests to test case */
  tcase_add_test (tc_internal, test_init_regions_and_queues);
  tcase_add_test (tc_internal, test_connect1);
  tcase_add_test (tc_internal, test_disconnect_internal);

  /* add test cases to test suite */
  suite_add_tcase (s, tc_api);
  suite_add_tcase (s, tc_internal);

  /* return main test suite to test runner */
  return s;
}
