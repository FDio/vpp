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

#include <socket_test.h>

#include <memif_private.h>
#include <socket.h>

static int
get_queue_len (memif_msg_queue_elt_t * q)
{
  int r = 0;
  memif_msg_queue_elt_t *c = q;
  while (c != NULL)
    {
      r++;
      c = c->next;
    }
  return r;
}

static void
queue_free (memif_msg_queue_elt_t ** e)
{
  if (*e == NULL)
    return;
  queue_free (&(*e)->next);
  free (*e);
  *e = NULL;
  return;
}

START_TEST (test_msg_queue)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t conn;
  conn.msg_queue = NULL;
  conn.fd = -1;


  int i, len = 10;

  for (i = 0; i < len; i++)
    {
      if (i % 2)
	memif_msg_enq_ack (&conn);
      else
	memif_msg_enq_init (&conn);
    }

  ck_assert_int_eq (len, get_queue_len (conn.msg_queue));

  int pop = 6;

  for (i = 0; i < pop; i++)
    {
      if (i % 2)
	{
	  ck_assert_uint_eq (conn.msg_queue->msg.type, MEMIF_MSG_TYPE_ACK);
	}
      else
	{
	  ck_assert_uint_eq (conn.msg_queue->msg.type, MEMIF_MSG_TYPE_INIT);
	}
      conn.flags |= MEMIF_CONNECTION_FLAG_WRITE;
      /* function will return -1 because no socket is created */
      memif_conn_fd_write_ready (&conn);
    }

  ck_assert_int_eq ((len - pop), get_queue_len (conn.msg_queue));

  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_enq_ack)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  memif_connection_t conn;
  conn.msg_queue = NULL;

  if ((err = memif_msg_enq_ack (&conn)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  memif_msg_queue_elt_t *e = conn.msg_queue;

  ck_assert_uint_eq (e->msg.type, MEMIF_MSG_TYPE_ACK);
  ck_assert_int_eq (e->fd, -1);
  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_enq_init)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  memif_connection_t conn;
  conn.msg_queue = NULL;

  conn.args.interface_id = 69;
  conn.args.mode = 0;

  strncpy ((char *) conn.args.secret, TEST_SECRET, strlen (TEST_SECRET));

  if ((err = memif_msg_enq_init (&conn)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_queue_elt_t *e = conn.msg_queue;

  ck_assert_uint_eq (e->msg.type, MEMIF_MSG_TYPE_INIT);
  ck_assert_int_eq (e->fd, -1);

  memif_msg_init_t *i = &e->msg.init;

  ck_assert_uint_eq (i->version, MEMIF_VERSION);
  ck_assert_uint_eq (i->id, conn.args.interface_id);
  ck_assert_uint_eq (i->mode, conn.args.mode);
  ck_assert_str_eq ((char *)i->secret, (char *)conn.args.secret);
  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_enq_add_region)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  memif_connection_t conn;
  conn.msg_queue = NULL;
  conn.regions = (memif_region_t *) malloc (sizeof (memif_region_t));
  memif_region_t *mr = conn.regions;
  mr->fd = 5;
  mr->region_size = 2048;
  uint8_t region_index = 0;

  if ((err =
       memif_msg_enq_add_region (&conn, region_index)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_queue_elt_t *e = conn.msg_queue;

  ck_assert_uint_eq (e->msg.type, MEMIF_MSG_TYPE_ADD_REGION);
  ck_assert_int_eq (e->fd, mr->fd);

  memif_msg_add_region_t *ar = &e->msg.add_region;

  ck_assert_uint_eq (ar->index, region_index);
  ck_assert_uint_eq (ar->size, mr->region_size);

  free (conn.regions);
  conn.regions = NULL;
  mr = NULL;
  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_enq_add_ring)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t conn;
  conn.msg_queue = NULL;
  conn.rx_queues = (memif_queue_t *) malloc (sizeof (memif_queue_t));
  conn.tx_queues = (memif_queue_t *) malloc (sizeof (memif_queue_t));

  memif_queue_t *mq = conn.tx_queues;
  uint8_t dir = MEMIF_RING_S2M;
  mq->int_fd = 5;
  mq->offset = 0;
  mq->log2_ring_size = 10;

  if ((err = memif_msg_enq_add_ring (&conn, 0, dir)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_queue_elt_t *e = conn.msg_queue;

  ck_assert_uint_eq (e->msg.type, MEMIF_MSG_TYPE_ADD_RING);
  ck_assert_int_eq (e->fd, mq->int_fd);

  memif_msg_add_ring_t *ar = &e->msg.add_ring;

  ck_assert_uint_eq (ar->index, 0);
  ck_assert_uint_eq (ar->offset, mq->offset);
  ck_assert_uint_eq (ar->log2_ring_size, mq->log2_ring_size);
  ck_assert (ar->flags & MEMIF_MSG_ADD_RING_FLAG_S2M);

  dir = MEMIF_RING_M2S;
  if ((err = memif_msg_enq_add_ring (&conn, 0, dir)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_enq_connect)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  memif_connection_t conn;
  conn.msg_queue = NULL;
  memset (conn.args.interface_name, 0, sizeof (conn.args.interface_name));
  strncpy ((char *) conn.args.interface_name, TEST_IF_NAME,
	   strlen (TEST_IF_NAME));

  if ((err = memif_msg_enq_connect (&conn)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_queue_elt_t *e = conn.msg_queue;

  ck_assert_uint_eq (e->msg.type, MEMIF_MSG_TYPE_CONNECT);
  ck_assert_int_eq (e->fd, -1);
  ck_assert_str_eq ((char *)e->msg.connect.if_name, TEST_IF_NAME);
  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_enq_connected)
{
  int err;
  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));
  memif_connection_t conn;
  conn.msg_queue = NULL;
  memset (conn.args.interface_name, 0, sizeof (conn.args.interface_name));
  strncpy ((char *) conn.args.interface_name, TEST_IF_NAME,
	   strlen (TEST_IF_NAME));

  if ((err = memif_msg_enq_connected (&conn)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_queue_elt_t *e = conn.msg_queue;

  ck_assert_uint_eq (e->msg.type, MEMIF_MSG_TYPE_CONNECTED);
  ck_assert_int_eq (e->fd, -1);
  ck_assert_str_eq ((char *)e->msg.connect.if_name, TEST_IF_NAME);
  queue_free (&conn.msg_queue);
}

END_TEST
START_TEST (test_send)
{
  int err;
  int fd = -1, afd = 5;
  memif_msg_t msg;
  memset (&msg, 0, sizeof (msg));

  if ((err = memif_msg_send (fd, &msg, afd)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_BAD_FD,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
}

END_TEST
START_TEST (test_send_hello)
{
  int err;
  memif_connection_t conn;
  conn.fd = -1;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if ((err = memif_msg_send_hello (conn.fd)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_BAD_FD,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
}

END_TEST
START_TEST (test_send_disconnect)
{
  int err;
  memif_connection_t conn;
  conn.fd = -1;

  /* only possible fail if memif_msg_send fails...  */
  /* obsolete without socket */
  if ((err =
       memif_msg_send_disconnect (conn.fd, (uint8_t *)"unit_test_dc",
				  0)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_BAD_FD, "err code: %u, err msg: %s", err,
		   memif_strerror (err));
}

END_TEST
START_TEST (test_recv_hello)
{
  int err;
  memif_connection_t conn;
  memif_msg_t msg;

  memif_msg_hello_t *h = &msg.hello;

  msg.type = MEMIF_MSG_TYPE_HELLO;

  h->min_version = MEMIF_VERSION;
  h->max_version = MEMIF_VERSION;
  h->max_s2m_ring = 1;
  h->max_m2s_ring = 1;
  h->max_log2_ring_size = 14;
  strncpy ((char *) h->name, TEST_IF_NAME, strlen (TEST_IF_NAME));
  memset (conn.remote_name, 0, sizeof (conn.remote_name));

  conn.args.num_s2m_rings = 4;
  conn.args.num_m2s_rings = 6;
  conn.args.log2_ring_size = 10;

  if ((err = memif_msg_receive_hello (&conn, &msg)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_uint_eq (conn.run_args.num_s2m_rings, 2);
  ck_assert_uint_eq (conn.run_args.num_m2s_rings, 2);
  ck_assert_uint_eq (conn.run_args.log2_ring_size, 10);
  ck_assert_str_eq ((char *)conn.remote_name, TEST_IF_NAME);

  h->max_version = 9;
  if ((err = memif_msg_receive_hello (&conn, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_PROTO,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
}

END_TEST
START_TEST (test_recv_init)
{
  int err;
  memif_connection_t conn;

  conn.args.interface_id = 69;
  conn.args.is_master = 1;
  conn.fd = -1;
  conn.args.mode = 0;
  memset (conn.args.secret, '\0', 24);
  strncpy ((char *) conn.args.secret, TEST_SECRET, strlen (TEST_SECRET));

  memif_msg_t msg;

  memif_msg_init_t *i = &msg.init;

  msg.type = MEMIF_MSG_TYPE_INIT;

  i->version = MEMIF_VERSION;
  i->id = 69;
  i->mode = 0;
  memset (i->name, '\0', 32);
  memset (i->secret, '\0', 24);
  strncpy ((char *) i->name, TEST_IF_NAME, strlen (TEST_IF_NAME));
  strncpy ((char *) i->secret, TEST_SECRET, strlen (TEST_SECRET));

  memif_socket_t ms;
  ms.interface_list_len = 1;
  ms.interface_list = malloc (sizeof (memif_list_elt_t));
  memif_list_elt_t elt;
  elt.key = 69;
  elt.data_struct = &conn;
  add_list_elt (&elt, &ms.interface_list, &ms.interface_list_len);

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  i->version = 9;
  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_PROTO,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
  i->version = MEMIF_VERSION;

  i->id = 78;
  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_ID,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
  i->id = 69;

  i->mode = 1;
  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_MODE,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
  i->mode = 0;

  i->secret[0] = '\0';
  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_SECRET,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
  strncpy ((char *) i->secret, TEST_SECRET, strlen (TEST_SECRET));

  conn.args.is_master = 0;
  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_ACCSLAVE,
		   "err code: %u, err msg: %s", err, memif_strerror (err));
  conn.args.is_master = 1;

  conn.fd = 5;
  if ((err = memif_msg_receive_init (&ms, -1, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg ((err == MEMIF_ERR_ALRCONN) || (err == MEMIF_ERR_BAD_FD),
		   "err code: %u, err msg: %s", err, memif_strerror (err));
}

END_TEST
START_TEST (test_recv_add_region)
{
  int err;
  memif_connection_t conn;
  conn.regions = NULL;
  memif_msg_t msg;
  msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  msg.add_region.size = 2048;
  msg.add_region.index = 0;

  int fd = 5;

  if ((err =
       memif_msg_receive_add_region (&conn, &msg, fd)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_region_t *mr = conn.regions;

  ck_assert_uint_eq (mr->fd, fd);
  ck_assert_uint_eq (mr->region_size, 2048);
  ck_assert_ptr_eq (mr->addr, NULL);
}

END_TEST
START_TEST (test_recv_add_ring)
{
  int err;
  memif_connection_t conn;
  int fd = 5;
  memif_msg_t msg;
  conn.args.num_s2m_rings = 2;
  conn.args.num_m2s_rings = 2;
  conn.rx_queues = NULL;
  conn.tx_queues = NULL;

  msg.type = MEMIF_MSG_TYPE_ADD_RING;
  memif_msg_add_ring_t *ar = &msg.add_ring;

  ar->log2_ring_size = 10;
  ar->region = 0;
  ar->offset = 0;
  ar->flags = 0;
  ar->flags |= MEMIF_MSG_ADD_RING_FLAG_S2M;
  ar->index = 1;

  if ((err =
       memif_msg_receive_add_ring (&conn, &msg, fd)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));


  ar->offset = 2048;
  ar->flags &= ~MEMIF_MSG_ADD_RING_FLAG_S2M;

  if ((err =
       memif_msg_receive_add_ring (&conn, &msg, fd)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

}

END_TEST
START_TEST (test_recv_connect)
{
  int err;
  memif_conn_handle_t c = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));

  args.interface_id = 0;
  args.is_master = 0;
  args.mode = 0;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if ((err = memif_create (&c, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *conn = (memif_connection_t *) c;

  conn->run_args.num_s2m_rings = 1;
  conn->run_args.num_m2s_rings = 1;
  conn->run_args.log2_ring_size = 10;
  conn->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (conn)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_t msg;
  memset (&msg, 0, sizeof (msg));
  msg.type = MEMIF_MSG_TYPE_CONNECT;

  memset (msg.connect.if_name, 0, sizeof (msg.connect.if_name));
  strncpy ((char *) msg.connect.if_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_msg_receive_connect (conn, &msg)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_str_eq ((char *)conn->remote_if_name, TEST_IF_NAME);
}

END_TEST
START_TEST (test_recv_connected)
{
  int err;
  memif_conn_handle_t c = NULL;
  memif_conn_args_t args;
  memset (&args, 0, sizeof (args));

  args.interface_id = 0;
  args.is_master = 0;
  args.mode = 0;

  if ((err =
       memif_init (control_fd_update, TEST_APP_NAME, NULL,
		   NULL, NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  if ((err = memif_create (&c, &args, on_connect,
			   on_disconnect, on_interrupt,
			   NULL)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_connection_t *conn = (memif_connection_t *) c;

  conn->run_args.num_s2m_rings = 1;
  conn->run_args.num_m2s_rings = 1;
  conn->run_args.log2_ring_size = 10;
  conn->run_args.buffer_size = 2048;

  if ((err = memif_init_regions_and_queues (conn)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  memif_msg_t msg;
  memset (&msg, 0, sizeof (msg));
  msg.type = MEMIF_MSG_TYPE_CONNECT;

  memset (msg.connect.if_name, 0, sizeof (msg.connect.if_name));
  strncpy ((char *) msg.connect.if_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

  if ((err = memif_msg_receive_connected (conn, &msg)) != MEMIF_ERR_SUCCESS)
    ck_abort_msg ("err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_str_eq ((char *)conn->remote_if_name, TEST_IF_NAME);
}

END_TEST
START_TEST (test_recv_disconnect)
{
  int err;
  memif_connection_t conn;
  memif_msg_t msg;
  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  memset (msg.disconnect.string, 0, sizeof (msg.disconnect.string));
  strncpy ((char *) msg.disconnect.string, "unit_test_dc", 12);

  if ((err = memif_msg_receive_disconnect (&conn, &msg)) != MEMIF_ERR_SUCCESS)
    ck_assert_msg (err == MEMIF_ERR_DISCONNECT,
		   "err code: %u, err msg: %s", err, memif_strerror (err));

  ck_assert_str_eq ((char *)conn.remote_disconnect_string, "unit_test_dc");
}

END_TEST Suite *
socket_suite ()
{
  Suite *s;
  TCase *tc_msg_queue;
  TCase *tc_msg_enq;
  TCase *tc_msg_send;
  TCase *tc_msg_recv;

  /* create socket test suite */
  s = suite_create ("Socket messaging");

  /* create msg queue test case */
  tc_msg_queue = tcase_create ("Message queue");
  /* add tests to test case */
  tcase_add_test (tc_msg_queue, test_msg_queue);

  /* create msg enq test case */
  tc_msg_enq = tcase_create ("Message enqueue");
  /* add tests to test case */
  tcase_add_test (tc_msg_enq, test_enq_ack);
  tcase_add_test (tc_msg_enq, test_enq_init);
  tcase_add_test (tc_msg_enq, test_enq_add_region);
  tcase_add_test (tc_msg_enq, test_enq_add_ring);
  tcase_add_test (tc_msg_enq, test_enq_connect);
  tcase_add_test (tc_msg_enq, test_enq_connected);

  /* create msg send test case */
  tc_msg_send = tcase_create ("Message send");
  /* add tests to test case */
  tcase_add_test (tc_msg_send, test_send);
  tcase_add_test (tc_msg_send, test_send_hello);
  tcase_add_test (tc_msg_send, test_send_disconnect);

  /* create msg recv test case */
  tc_msg_recv = tcase_create ("Message receive");
  /* add tests to test case */
  tcase_add_test (tc_msg_recv, test_recv_hello);
  tcase_add_test (tc_msg_recv, test_recv_init);
  tcase_add_test (tc_msg_recv, test_recv_add_region);
  tcase_add_test (tc_msg_recv, test_recv_add_ring);
  tcase_add_test (tc_msg_recv, test_recv_connect);
  tcase_add_test (tc_msg_recv, test_recv_connected);
  tcase_add_test (tc_msg_recv, test_recv_disconnect);

  /* add test cases to test suite */
  suite_add_tcase (s, tc_msg_queue);
  suite_add_tcase (s, tc_msg_enq);
  suite_add_tcase (s, tc_msg_send);
  suite_add_tcase (s, tc_msg_recv);

  /* return socket test suite to test runner */
  return s;
}
