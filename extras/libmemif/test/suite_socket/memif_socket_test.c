#include <main.c>
#include <socket.c>

#include <unity_fixture.h>
#include <libmemif.h>
#include <memif_private.h>
#include <stdlib.h>

#define TEST_APP_NAME	   "unit_test_app"
#define MEMIF_TEST_IF_NAME "unit_test_if"
#define MEMIF_TEST_SECRET  "psst"
#define TEST_IF_ID	   0
#define TEST_SOCKET_PATH   "@memif.sock"

#undef malloc
#undef calloc
#undef realloc
#undef free

static int err;
static memif_socket_handle_t memif_socket;
static memif_socket_args_t memif_socket_args;
static memif_control_channel_t *cc;

static void
init_socket_args ()
{
  strncpy (memif_socket_args.app_name, MEMIF_DEFAULT_APP_NAME,
	   strlen (MEMIF_DEFAULT_APP_NAME));
  sprintf (memif_socket_args.path, "%s", MEMIF_DEFAULT_SOCKET_PATH);
}

TEST_GROUP (MemifSocket);

TEST_SETUP (MemifSocket)
{
  memif_socket = NULL;
  static int err = 0;
}

TEST_TEAR_DOWN (MemifSocket) {}

TEST (MemifSocket, CreateSocket)
{

  memif_socket_args_t memif_socket_args = {
    .app_name = TEST_APP_NAME,
    .path = TEST_SOCKET_PATH,
  };
  err = memif_create_socket (&memif_socket, &memif_socket_args, NULL);

  TEST_ASSERT_EQUAL_INT (0, err);
  TEST_ASSERT_NOT_NULL (memif_socket);

  memif_socket_t *ms = (memif_socket_t *) memif_socket;

  TEST_ASSERT_EQUAL_STRING (ms->args.app_name, TEST_APP_NAME);
  TEST_ASSERT_EQUAL_STRING (ms->args.path, TEST_SOCKET_PATH);
  TEST_ASSERT_EQUAL_PTR (ms->args.on_control_fd_update,
			 memif_control_fd_update);
  TEST_ASSERT_EQUAL_PTR (ms->args.alloc, malloc);
  TEST_ASSERT_EQUAL_PTR (ms->args.realloc, realloc);
  TEST_ASSERT_EQUAL_PTR (ms->args.free, free);

  TEST_ASSERT_NOT_EQUAL_INT (ms->epfd, -1);
  TEST_ASSERT_NOT_EQUAL_INT (ms->poll_cancel_fd, -1);

  memif_delete_socket (&memif_socket);
}

TEST (MemifSocket, DeleteSocket)
{

  memif_socket_args_t memif_socket_args = {
    .app_name = TEST_APP_NAME,
    .path = TEST_SOCKET_PATH,
  };
  memif_create_socket (&memif_socket, &memif_socket_args, NULL);

  memif_socket_t *ms = (memif_socket_t *) memif_socket;
  err = memif_delete_socket (&memif_socket);
  TEST_ASSERT_EQUAL_INT (MEMIF_ERR_SUCCESS, err);
  TEST_ASSERT_NULL (memif_socket);
}

TEST_GROUP (MemifControlChannel);

TEST_SETUP (MemifControlChannel)
{
  memif_socket = NULL;
  static int err = 0;
  init_socket_args ();
  memif_create_socket (&memif_socket, &memif_socket_args, NULL);
  cc = (memif_control_channel_t *) malloc (sizeof (memif_control_channel_t));
}

TEST_TEAR_DOWN (MemifControlChannel) { free (cc); }

TEST (MemifControlChannel, EnqAck)
{
  memif_connection_t conn;
  memif_msg_queue_elt_t *e;
  cc->fd = 5;
  cc->conn = NULL;
  cc->sock = memif_socket;

  TAILQ_INIT (&cc->msg_queue);
  memif_msg_enq_ack (cc);

  e = TAILQ_FIRST (&cc->msg_queue);

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_ACK, e->msg.type);
  TEST_ASSERT_EQUAL_INT (-1, e->fd);
}

TEST (MemifControlChannel, EnqHello)
{
  memif_connection_t conn;
  memif_msg_queue_elt_t *e;
  cc->fd = 5;
  cc->conn = NULL;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  memif_msg_enq_hello (cc);

  e = TAILQ_FIRST (&cc->msg_queue);

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_HELLO, e->msg.type);
  TEST_ASSERT_EQUAL_INT (-1, e->fd);
  memif_msg_hello_t h = e->msg.hello;
  TEST_ASSERT_EQUAL_INT (MEMIF_MAX_LOG2_RING_SIZE, h.max_log2_ring_size);
  TEST_ASSERT_EQUAL_INT (MEMIF_VERSION, h.min_version);
  TEST_ASSERT_EQUAL_INT (MEMIF_VERSION, h.max_version);
  TEST_ASSERT_EQUAL_INT (MEMIF_MAX_S2M_RING, h.max_s2m_ring);
  TEST_ASSERT_EQUAL_INT (MEMIF_MAX_M2S_RING, h.max_m2s_ring);
  TEST_ASSERT_EQUAL_INT (MEMIF_MAX_REGION, h.max_region);
}

TEST (MemifControlChannel, EnqInit)
{
  memif_msg_queue_elt_t *e;
  memif_connection_t conn;
  cc->fd = 5;
  cc->conn = &conn;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  conn.args.interface_id = 11;
  conn.args.mode = 1;
  strlcpy ((char *) conn.args.secret, MEMIF_TEST_SECRET,
	   sizeof (MEMIF_TEST_SECRET));

  memif_socket_t *ms = (memif_socket_t *) memif_socket;

  memif_msg_enq_init (cc);

  e = TAILQ_FIRST (&cc->msg_queue);

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_INIT, e->msg.type);
  TEST_ASSERT_EQUAL_INT (-1, e->fd);
  memif_msg_init_t h = e->msg.init;

  TEST_ASSERT_EQUAL_INT (11, h.id);
  TEST_ASSERT_EQUAL_INT (1, h.mode);
  TEST_ASSERT_EQUAL_STRING (MEMIF_DEFAULT_APP_NAME, h.name);
  TEST_ASSERT_EQUAL_STRING (MEMIF_TEST_SECRET, h.secret);
  TEST_ASSERT_EQUAL_INT (MEMIF_VERSION, h.version);
}

TEST (MemifControlChannel, EnqAddRegion)
{
  memif_msg_queue_elt_t *e;
  memif_connection_t conn;
  memset (cc, 0, sizeof (memif_msg_queue_elt_t));
  memset (&conn, 0, sizeof (memif_connection_t));

  cc->fd = 5;
  cc->conn = &conn;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  conn.args.interface_id = 11;
  conn.args.mode = 1;
  conn.args.socket = memif_socket;
  strlcpy ((char *) conn.args.secret, MEMIF_TEST_SECRET,
	   sizeof (MEMIF_TEST_SECRET));

  memif_socket_t *ms = (memif_socket_t *) memif_socket;

  conn.run_args.num_s2m_rings = 1;
  conn.run_args.num_m2s_rings = 1;
  conn.run_args.log2_ring_size = MEMIF_DEFAULT_LOG2_RING_SIZE;
  conn.run_args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  memif_add_region (&conn, 1);

  memif_msg_enq_add_region (cc, 0);

  e = TAILQ_FIRST (&cc->msg_queue);
  memif_msg_add_region_t h = e->msg.add_region;

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_ADD_REGION, e->msg.type);
  TEST_ASSERT_EQUAL_INT (conn.regions[0].fd, e->fd);

  TEST_ASSERT_EQUAL_INT (0, h.index);
  TEST_ASSERT_EQUAL_INT (conn.regions[0].region_size, h.size);

  close (conn.regions[0].fd);
}

TEST (MemifControlChannel, EnqAddRing)
{
  memif_msg_queue_elt_t *e;
  memif_connection_t conn;
  memset (cc, 0, sizeof (memif_msg_queue_elt_t));
  memset (&conn, 0, sizeof (memif_connection_t));

  cc->fd = 5;
  cc->conn = &conn;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  conn.args.interface_id = 11;
  conn.args.mode = 1;
  conn.args.socket = memif_socket;
  strlcpy ((char *) conn.args.secret, MEMIF_TEST_SECRET,
	   sizeof (MEMIF_TEST_SECRET));

  memif_socket_t *ms = (memif_socket_t *) memif_socket;

  conn.run_args.num_s2m_rings = 1;
  conn.run_args.num_m2s_rings = 1;
  conn.run_args.log2_ring_size = MEMIF_DEFAULT_LOG2_RING_SIZE;
  conn.run_args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  memif_add_region (&conn, 1);
  memif_init_queues (&conn);
  memif_msg_enq_add_ring (cc, 0, MEMIF_RING_M2S);

  e = TAILQ_FIRST (&cc->msg_queue);
  memif_msg_add_ring_t h = e->msg.add_ring;

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_ADD_RING, e->msg.type);
  TEST_ASSERT_EQUAL_INT (conn.rx_queues[0].int_fd, e->fd);

  TEST_ASSERT_EQUAL_INT (0, h.flags);
  TEST_ASSERT_EQUAL_INT (0, h.index);
  TEST_ASSERT_EQUAL_INT (conn.rx_queues[0].region, h.region);
  TEST_ASSERT_EQUAL_INT (conn.rx_queues[0].offset, h.offset);
  TEST_ASSERT_EQUAL_INT (conn.rx_queues[0].log2_ring_size, h.log2_ring_size);
  TEST_ASSERT_EQUAL_INT (0, h.private_hdr_size);

  close (conn.regions[0].fd);
}
TEST (MemifControlChannel, EnqConnect)
{
  memif_msg_queue_elt_t *e;
  memif_connection_t conn;
  memset (cc, 0, sizeof (memif_msg_queue_elt_t));
  memset (&conn, 0, sizeof (memif_connection_t));

  cc->fd = 5;
  cc->conn = &conn;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  conn.args.interface_id = 11;
  conn.args.mode = 1;
  conn.args.socket = memif_socket;
  strlcpy ((char *) conn.args.secret, MEMIF_TEST_SECRET,
	   sizeof (MEMIF_TEST_SECRET));
  strlcpy ((char *) conn.args.interface_name, MEMIF_TEST_IF_NAME,
	   sizeof (MEMIF_TEST_IF_NAME));

  memif_socket_t *ms = (memif_socket_t *) memif_socket;

  conn.run_args.num_s2m_rings = 1;
  conn.run_args.num_m2s_rings = 1;
  conn.run_args.log2_ring_size = MEMIF_DEFAULT_LOG2_RING_SIZE;
  conn.run_args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  memif_add_region (&conn, 1);
  memif_init_queues (&conn);
  memif_msg_enq_connect (cc);

  e = TAILQ_FIRST (&cc->msg_queue);
  memif_msg_connect_t h = e->msg.connect;

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_CONNECT, e->msg.type);
  TEST_ASSERT_EQUAL_INT (-1, e->fd);

  TEST_ASSERT_EQUAL_STRING (MEMIF_TEST_IF_NAME, h.if_name);

  close (conn.regions[0].fd);
}

TEST (MemifControlChannel, EnqConnected)
{
  memif_msg_queue_elt_t *e;
  memif_connection_t conn;
  memset (cc, 0, sizeof (memif_msg_queue_elt_t));
  memset (&conn, 0, sizeof (memif_connection_t));

  cc->fd = 5;
  cc->conn = &conn;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  conn.args.interface_id = 11;
  conn.args.mode = 1;
  conn.args.socket = memif_socket;
  strlcpy ((char *) conn.args.secret, MEMIF_TEST_SECRET,
	   sizeof (MEMIF_TEST_SECRET));
  strlcpy ((char *) conn.args.interface_name, MEMIF_TEST_IF_NAME,
	   sizeof (MEMIF_TEST_IF_NAME));

  memif_socket_t *ms = (memif_socket_t *) memif_socket;

  conn.run_args.num_s2m_rings = 1;
  conn.run_args.num_m2s_rings = 1;
  conn.run_args.log2_ring_size = MEMIF_DEFAULT_LOG2_RING_SIZE;
  conn.run_args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;

  memif_add_region (&conn, 1);
  memif_init_queues (&conn);
  memif_msg_enq_connect (cc);

  e = TAILQ_FIRST (&cc->msg_queue);
  memif_msg_connected_t h = e->msg.connected;

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_CONNECT, e->msg.type);
  TEST_ASSERT_EQUAL_INT (-1, e->fd);

  TEST_ASSERT_EQUAL_STRING (MEMIF_TEST_IF_NAME, h.if_name);

  close (conn.regions[0].fd);
}

TEST (MemifControlChannel, EnqDisconnect)
{
  memif_msg_queue_elt_t *e;
  memif_connection_t conn;
  memset (cc, 0, sizeof (memif_msg_queue_elt_t));
  memset (&conn, 0, sizeof (memif_connection_t));

  cc->fd = 5;
  cc->conn = &conn;
  cc->sock = memif_socket;
  TAILQ_INIT (&cc->msg_queue);

  conn.args.interface_id = 11;
  conn.args.mode = 1;
  conn.args.socket = memif_socket;
  strlcpy ((char *) conn.args.secret, MEMIF_TEST_SECRET,
	   sizeof (MEMIF_TEST_SECRET));
  strlcpy ((char *) conn.args.interface_name, MEMIF_TEST_IF_NAME,
	   sizeof (MEMIF_TEST_IF_NAME));

  memif_socket_t *ms = (memif_socket_t *) memif_socket;
  memif_msg_enq_disconnect (cc, "TEST", 5);

  e = TAILQ_FIRST (&cc->msg_queue);
  memif_msg_disconnect_t h = e->msg.disconnect;

  TEST_ASSERT_EQUAL_UINT16 (MEMIF_MSG_TYPE_DISCONNECT, e->msg.type);
  TEST_ASSERT_EQUAL_INT (-1, e->fd);

  TEST_ASSERT_EQUAL_INT (5, h.code);
  TEST_ASSERT_EQUAL_STRING ("TEST", h.string);
}

TEST_GROUP_RUNNER (MemifSocket){ RUN_TEST_CASE (MemifSocket, CreateSocket)
				   RUN_TEST_CASE (MemifSocket, DeleteSocket)

}

TEST_GROUP_RUNNER (MemifControlChannel)
{
  RUN_TEST_CASE (MemifControlChannel, EnqAck)
  RUN_TEST_CASE (MemifControlChannel, EnqHello)
  RUN_TEST_CASE (MemifControlChannel, EnqInit)
  RUN_TEST_CASE (MemifControlChannel, EnqAddRegion)
  RUN_TEST_CASE (MemifControlChannel, EnqAddRing)
  RUN_TEST_CASE (MemifControlChannel, EnqConnect)
  RUN_TEST_CASE (MemifControlChannel, EnqConnected)
  RUN_TEST_CASE (MemifControlChannel, EnqDisconnect)
}

static void
RunAllTests (void)
{
  RUN_TEST_GROUP (MemifSocket);
  RUN_TEST_GROUP (MemifControlChannel);
}

int
main (int argc, const char *argv[])
{
  return UnityMain (argc, argv, RunAllTests);
}
