#include <main.c>
#include <unity_fixture.h>
#include <memif_private.h>
#include <stdlib.h>

#define MEMIF_VERSION_STR    "2.0"
#define MEMIF_BUFFER_SIZE    2048
#define MEMIF_INTERFACE_NAME "memif0/0"
#define MEMIF_LOG_RING_SIZE  10
#define MEMIF_SECRET	     "psst"

#undef malloc
#undef calloc
#undef realloc
#undef free

static memif_socket_handle_t socket_handler;
static memif_conn_handle_t conn;

static memif_socket_args_t memif_socket_args;
static memif_conn_args_t memif_conn_args;

static int dummy_on_connect (void *, void *);
static int dummy_on_disconnect (void *, void *);
static int dummy_on_interrupt (void *, void *, uint16_t);

static int
dummy_on_connect (void *a, void *b)
{
}
static int
dummy_on_disconnect (void *a, void *b)
{
}
static int
dummy_on_interrupt (void *a, void *b, uint16_t c)
{
}

static void
init_conn_args ()
{
  memif_connection_t *c = (memif_connection_t *) conn;
  memset (c, 0, sizeof (memif_connection_t));
  c->args = (memif_conn_args_t){ .buffer_size = MEMIF_BUFFER_SIZE,
				 .interface_id = 0,
				 .interface_name = MEMIF_INTERFACE_NAME,
				 .is_master = 0,
				 .log2_ring_size = MEMIF_LOG_RING_SIZE,
				 .mode = 0,
				 .num_m2s_rings = 1,
				 .num_s2m_rings = 1,
				 .secret = MEMIF_SECRET,
				 .socket = &socket_handler };
}

static void
init_connection ()
{
  conn = malloc (sizeof (memif_connection_t));
  memif_connection_t *c = (memif_connection_t *) conn;
  init_conn_args ();
}

static void
init_socket ()
{
  memif_socket_t *ms = malloc (sizeof (memif_socket_t));
  socket_handler = ms;
  /* default values */
  memset (ms, 0, sizeof (memif_socket_t));
  ms->epfd = 3;
  ms->listener_fd = 4;
  ms->poll_cancel_fd = 5;
  ms->timer_fd = -1;

  TAILQ_INIT (&ms->master_interfaces);
  TAILQ_INIT (&ms->slave_interfaces);
}

static void
init_socket_args ()
{
  strncpy (memif_socket_args.app_name, MEMIF_DEFAULT_APP_NAME,
	   strlen (MEMIF_DEFAULT_APP_NAME));
  strncpy (memif_socket_args.path, MEMIF_DEFAULT_SOCKET_PATH,
	   strlen (MEMIF_DEFAULT_SOCKET_PATH));
}

static void
delete_connection ()
{
  free (conn);
}

TEST_GROUP (MemifMain);

TEST_SETUP (MemifMain) {}

TEST_TEAR_DOWN (MemifMain) {}

TEST (MemifMain, MemifGetVersion)
{
  TEST_ASSERT_EQUAL_UINT16 (MEMIF_VERSION, memif_get_version ());
}

TEST (MemifMain, MemifGetVersionStr)
{
  TEST_ASSERT_EQUAL_STRING (MEMIF_VERSION_STR, memif_get_version_str ());
}

TEST (MemifMain, MemifStrError)
{
  for (size_t i = 0; i < ERRLIST_LEN; i++)
    {
      TEST_ASSERT_EQUAL_STRING (memif_strerror (0), memif_errlist[0]);
    }
  TEST_ASSERT_EQUAL_STRING (memif_strerror (ERRLIST_LEN + 1),
			    MEMIF_ERR_UNDEFINED);
}

TEST (MemifMain, MemifGetDetails)
{
  init_socket ();
  init_connection ();
  memif_details_t md;
  ssize_t buflen = 2048;
  char buf[buflen];
  memif_get_details (conn, &md, buf, buflen);

  TEST_ASSERT_EQUAL_STRING (MEMIF_INTERFACE_NAME, md.if_name);
  TEST_ASSERT_EQUAL_UINT64 (0, md.id);
}

TEST (MemifMain, MemifControl_fd_update_add_del_epoll_fd)
{
  init_socket_args ();
  memif_create_socket (&socket_handler, &memif_socket_args, NULL);
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  void *ctx;
  memif_socket_t *ms = (memif_socket_t *) socket_handler;

  fdata = ms->args.alloc (sizeof (*fdata));
  fdata->event_handler = memif_poll_cancel_handler;
  fdata->private_ctx = ms;

  fde.fd = eventfd (0, EFD_NONBLOCK);
  fde.private_ctx = fdata;
  fde.type = MEMIF_FD_EVENT_READ;
  ctx = ms->epfd != -1 ? ms : ms->private_ctx;
  TEST_ASSERT_EQUAL_INT (0, memif_control_fd_update (fde, ctx));
  fde.type = MEMIF_FD_EVENT_DEL;
  TEST_ASSERT_EQUAL_INT (0, memif_control_fd_update (fde, ctx));
}

TEST (MemifMain, MemifSetConnectionRequestTimer)
{
  memif_socket_handle_t msh =
    (memif_socket_handle_t) malloc (sizeof (memif_socket_t));
  memif_socket_t *ms = (memif_socket_t *) msh;
  struct itimerspec timer;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  int i, err = MEMIF_ERR_SUCCESS;
  void *ctx;
  memset (ms, 0, sizeof (memif_socket_t));
  ms->epfd = -1;
  ms->listener_fd = -1;
  ms->poll_cancel_fd = -1;

  TAILQ_INIT (&ms->master_interfaces);
  TAILQ_INIT (&ms->slave_interfaces);
  ms->timer_fd = -1;
  ms->args.alloc = malloc;
  ms->args.free = free;
  ms->args.realloc = realloc;

  if (ms->args.on_control_fd_update == NULL)
    {
      ms->epfd = epoll_create (1);
      memif_control_fd_update_register (ms, memif_control_fd_update);
      ms->poll_cancel_fd = eventfd (0, EFD_NONBLOCK);

      fdata = ms->args.alloc (sizeof (*fdata));
      fdata->event_handler = memif_poll_cancel_handler;
      fdata->private_ctx = ms;

      fde.fd = ms->poll_cancel_fd;
      fde.type = MEMIF_FD_EVENT_READ;
      fde.private_ctx = fdata;
      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);
    }

  timer.it_value.tv_sec = 2;
  timer.it_value.tv_nsec = 0;
  timer.it_interval.tv_sec = 2;
  timer.it_value.tv_nsec = 0;
  memif_set_connection_request_timer (msh, timer);

  TEST_ASSERT_NOT_EQUAL_INT (-1, ms->timer_fd);
  memif_delete_socket (&msh);
}

TEST (MemifMain, MemifSetConnectionRequestTimerNoTimer)
{
  memif_socket_handle_t msh =
    (memif_socket_handle_t) malloc (sizeof (memif_socket_t));
  memif_socket_t *ms = (memif_socket_t *) msh;
  struct itimerspec timer;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  int i, err = MEMIF_ERR_SUCCESS;
  void *ctx;
  memset (ms, 0, sizeof (memif_socket_t));
  ms->epfd = -1;
  ms->listener_fd = -1;
  ms->poll_cancel_fd = -1;

  TAILQ_INIT (&ms->master_interfaces);
  TAILQ_INIT (&ms->slave_interfaces);
  ms->timer_fd = -1;
  ms->args.alloc = malloc;
  ms->args.free = free;
  ms->args.realloc = realloc;

  if (ms->args.on_control_fd_update == NULL)
    {
      ms->epfd = epoll_create (1);
      /* register default fd update callback */
      memif_control_fd_update_register (ms, memif_control_fd_update);
      ms->poll_cancel_fd = eventfd (0, EFD_NONBLOCK);
      if (ms->poll_cancel_fd < 0)
	{
	  err = errno;
	  DBG ("eventfd: %s", strerror (err));
	  // return memif_syscall_error_handler (err);
	}
      /* add interrupt fd to epfd */
      fdata = ms->args.alloc (sizeof (*fdata));
      fdata->event_handler = memif_poll_cancel_handler;
      fdata->private_ctx = ms;

      fde.fd = ms->poll_cancel_fd;
      fde.type = MEMIF_FD_EVENT_READ;
      fde.private_ctx = fdata;
      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);
    }
  memset (&timer, 0, sizeof (struct itimerspec));
  memif_set_connection_request_timer (msh, timer);

  TEST_ASSERT_EQUAL_INT (-1, ms->timer_fd);
  memif_delete_socket (msh);
  memif_delete_socket (&msh);
}

TEST_GROUP (MemifInterface);

TEST_SETUP (MemifInterface)
{
  socket_handler = NULL;
  conn = NULL;
  memset (&memif_socket_args, 0, sizeof (memif_socket_args_t));
  memset (&memif_conn_args, 0, sizeof (memif_conn_args_t));

  memif_socket_args = (memif_socket_args_t){
    .app_name = "TEST",
    .path = "@memif.sock",
  };
  int err = memif_create_socket (&socket_handler, &memif_socket_args, NULL);
  if (err)
    exit (EXIT_FAILURE);
  memif_conn_args.socket = socket_handler;
  memif_conn_args.interface_id = 0;
  strncpy (memif_conn_args.interface_name, MEMIF_INTERFACE_NAME,
	   sizeof (memif_conn_args.interface_name));
}

TEST_TEAR_DOWN (MemifInterface)
{
  memif_delete (&conn);
  memif_delete_socket (&socket_handler);
  memset (&memif_socket_args, 0, sizeof (memif_socket_args_t));
  memset (&memif_conn_args, 0, sizeof (memif_conn_args_t));
  memif_delete (&conn);
}

TEST (MemifInterface, MemifCreateMaster)
{
  memif_conn_args.is_master = 1;
  int err = memif_create (&conn, &memif_conn_args, dummy_on_connect,
			  dummy_on_disconnect, dummy_on_interrupt, NULL);

  TEST_ASSERT_EQUAL_INT (MEMIF_ERR_SUCCESS, err);

  memif_socket_t *ms = (memif_socket_t *) socket_handler;
  memif_connection_t *mc = conn;

  TEST_ASSERT_NULL (ms->slave_interfaces.tqh_first);
  TEST_ASSERT_NOT_NULL (ms->master_interfaces.tqh_first);
  TEST_ASSERT_NOT_NULL (mc->args.socket);
  TEST_ASSERT_EQUAL_INT (mc->args.buffer_size, MEMIF_DEFAULT_BUFFER_SIZE);
  TEST_ASSERT_EQUAL_UINT8 (mc->args.log2_ring_size,
			   MEMIF_DEFAULT_LOG2_RING_SIZE);
  TEST_ASSERT_EQUAL_UINT8 (mc->args.num_m2s_rings, 1);
  TEST_ASSERT_EQUAL_UINT8 (mc->args.num_s2m_rings, 1);
}
TEST (MemifInterface, MemifCreateSlave)
{
  memif_conn_args.is_master = 0;

  int err = memif_create (&conn, &memif_conn_args, dummy_on_connect,
			  dummy_on_disconnect, dummy_on_interrupt, NULL);

  memif_socket_t *ms = (memif_socket_t *) socket_handler;
  memif_connection_t *mc = conn;

  TEST_ASSERT_EQUAL_INT (MEMIF_ERR_SUCCESS, err);
  TEST_ASSERT_NULL (ms->master_interfaces.tqh_first);
  TEST_ASSERT_NOT_NULL (ms->slave_interfaces.tqh_first);
  TEST_ASSERT_NOT_NULL (mc->args.socket);
  TEST_ASSERT_EQUAL_INT (mc->args.buffer_size, MEMIF_DEFAULT_BUFFER_SIZE);
  TEST_ASSERT_EQUAL_UINT8 (mc->args.log2_ring_size,
			   MEMIF_DEFAULT_LOG2_RING_SIZE);
  TEST_ASSERT_EQUAL_UINT8 (mc->args.num_m2s_rings, 1);
  TEST_ASSERT_EQUAL_UINT8 (mc->args.num_s2m_rings, 1);
}

TEST (MemifInterface, MemifDelete)
{
  memif_conn_args.is_master = 0;

  memif_create (&conn, &memif_conn_args, dummy_on_connect, dummy_on_disconnect,
		dummy_on_interrupt, NULL);

  int err = memif_delete (&conn);

  TEST_ASSERT_EQUAL_INT (MEMIF_ERR_SUCCESS, err);
  TEST_ASSERT_NULL (conn);
}

TEST (MemifMain, MemifPollEvent)
{
  init_socket_args ();
  memif_create_socket (&socket_handler, &memif_socket_args, NULL);
  memif_socket_t *ms = (memif_socket_t *) socket_handler;
  uint64_t buf = 1;
  int ret = write (ms->poll_cancel_fd, &buf, sizeof (buf));
  TEST_ASSERT_EQUAL (8, ret);
  TEST_ASSERT_EQUAL (MEMIF_ERR_POLL_CANCEL,
		     memif_poll_event (socket_handler, -1));
}

TEST_GROUP_RUNNER (MemifMain){
  RUN_TEST_CASE (MemifMain, MemifGetVersion)
    RUN_TEST_CASE (MemifMain, MemifGetVersionStr)
      RUN_TEST_CASE (MemifMain, MemifStrError)
	RUN_TEST_CASE (MemifMain, MemifGetDetails)
	  RUN_TEST_CASE (MemifMain, MemifControl_fd_update_add_del_epoll_fd)
	    RUN_TEST_CASE (MemifMain, MemifSetConnectionRequestTimer)
	      RUN_TEST_CASE (MemifMain, MemifSetConnectionRequestTimerNoTimer)
		RUN_TEST_CASE (MemifMain, MemifPollEvent)

}

TEST_GROUP_RUNNER (MemifInterface)
{
  RUN_TEST_CASE (MemifInterface, MemifCreateMaster);
  RUN_TEST_CASE (MemifInterface, MemifCreateSlave);
  RUN_TEST_CASE (MemifInterface, MemifDelete);
}
static void
RunAllTests (void)
{
  RUN_TEST_GROUP (MemifMain);
  RUN_TEST_GROUP (MemifInterface);
}

int
main (int argc, const char *argv[])
{
  return UnityMain (argc, argv, RunAllTests);
}
