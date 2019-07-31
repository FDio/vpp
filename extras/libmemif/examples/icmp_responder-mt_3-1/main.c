#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <libmemif.h>
#include <icmp_proto.h>


#define APP_NAME "ICMP_Responder_mt_v3.1"
#define IF_NAME  "memif_connection"

#ifdef ICMP_DBG
#define DBG(...) do {                                               \
                    printf (APP_NAME":%s:%d: ", __func__, __LINE__);         \
                    printf (__VA_ARGS__);                           \
                    printf ("\n");                                  \
                } while (0)
#else
#define DBG(...)
#endif

#define ICMPR_BUFFER_LENGTH		32
#define ICMPR_SOCKET_FILENAME_LEN	256

static struct option options[] = {
	{"threads", required_argument, 0, 't'},
	{"if_num", required_argument, 0, 'i'}
};

struct memif_connection
{
	uint16_t id;
	bool connected;
	struct per_thread_data *ptd;
	memif_conn_handle_t handle;
	uint8_t ip_addr[4];
};

struct per_thread_data
{
	bool running;
	uint8_t index;
	int epfd;
	int pcfd; /* poll cancel file descriptor */
	uint16_t if_num;
	struct memif_connection *conns;
	memif_per_thread_main_handle_t pt_main;
	memif_socket_handle_t socket_handle;
};

struct icmpr_main
{
	uint8_t threads;
	uint16_t per_thread_if_num;
	struct per_thread_data *ptd;
	pthread_t *pthread;
};

struct icmpr_main icmpr_main;

int
add_epoll_fd (int epfd, int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset(&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
      DBG("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG("fd %d added to epoll", fd);
  return 0;
}

int
mod_epoll_fd (int epfd, int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
      DBG("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG("fd %d moddified on epoll", fd);
  return 0;
}

int
del_epoll_fd (int epfd, int fd)
{
  if (fd < 0)
    {
      DBG("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset(&evt, 0, sizeof (evt));
  if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
      DBG("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG("fd %d removed from epoll", fd);
  return 0;
}

static int
control_fd_update (int fd, uint8_t events, void *private_ctx)
{
	struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
	uint32_t evt = 0;

	if (ptd == NULL)
		return -1;

	/* convert memif event definitions to epoll events */
	if (events & MEMIF_FD_EVENT_DEL)
	  return del_epoll_fd (ptd->epfd, fd);

	if (events & MEMIF_FD_EVENT_READ)
	  evt |= EPOLLIN;
	if (events & MEMIF_FD_EVENT_WRITE)
	  evt |= EPOLLOUT;

	if (events & MEMIF_FD_EVENT_MOD)
	  return mod_epoll_fd (ptd->epfd, fd, evt);

	return add_epoll_fd (ptd->epfd, fd, evt);
}

static int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
	struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
	struct memif_connection *c;
	int i = 0;

	while (i < ptd->if_num && ptd->conns[i].handle != conn)
		i++;

	c = ptd->conns[i].handle;

	c->connected = true;
	DBG ("Connected: %u", c->id);

	memif_refill_queue (conn, 0, -1, 0);

	return 0;
}

static int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
	struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
	struct memif_connection *c;
	int i = 0;

	while (i < ptd->if_num && ptd->conns[i].handle != conn)
		i++;

	c = ptd->conns[i].handle;
	c->connected = false;
	DBG ("Disconnected: %u", c->id);

	return 0;
}

static int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
	struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
	struct memif_connection *c;
	memif_buffer_t mbufs[256];
	uint16_t rx = 0;
	uint16_t tx = 0;
	uint16_t ret;
	memif_err_t err;
	int i = 0;

	memset (mbufs, 0, 256);

	while (i < ptd->if_num && ptd->conns[i].handle != conn)
		i++;

	c = ptd->conns[i].handle;

	/* receive data from shared memory buffers */
        err = memif_rx_burst (conn, qid, mbufs, 256, &rx);
	printf ("%s\n", memif_strerror (err));

	for (i = 0; i < rx; i++)
  	{
  	  resolve_packet2 (&mbufs[i].data, &mbufs[i].len, c->ip_addr);
  	}

	err = memif_buffer_enq_tx (conn, qid, mbufs, i, &tx);
	printf ("%s\n", memif_strerror (err));

        /* mark shared memory buffers as free */
        err = memif_refill_queue (conn, qid, rx, 0);
	printf ("%s\n", memif_strerror (err));

        err = memif_tx_burst (conn, qid, mbufs, tx, &ret);
	printf ("%s\n", memif_strerror (err));

	return 0;
}

int
poll_event (memif_per_thread_main_handle_t pt_main, int pcfd, int epfd, int timeout)
{
  struct epoll_event evt;
  int en = 0;
  uint8_t events = 0;
  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;

  en = epoll_pwait (epfd, &evt, 1, timeout, NULL);
  if (en < 0) {
      printf ("epoll_pwait: %s\n", strerror (errno));
      return -1;
    }

  if (en > 0) {
	if (evt.data.fd == pcfd)
		return 1;

	if (evt.events & EPOLLIN)
		events |= MEMIF_FD_EVENT_READ;
	if (evt.events & EPOLLOUT)
		events |= MEMIF_FD_EVENT_WRITE;
	if (evt.events & EPOLLERR)
		events |= MEMIF_FD_EVENT_ERROR;

	memif_per_thread_control_fd_handler (pt_main, evt.data.fd, events);
    }

  return 0;
}

static void *
icmpr_thread_fn (void *data)
{
	struct per_thread_data *ptd = (struct per_thread_data *) data;
	int rv;
	uint16_t i;
	char socket_filename[ICMPR_SOCKET_FILENAME_LEN] = "/run/vpp/memif";
	memif_conn_args_t args;

	ptd->epfd = epoll_create (1);

	ptd->conns = malloc (sizeof (struct memif_connection) * ptd->if_num);
	if (ptd->conns == NULL) {
		printf("%s\n", strerror (errno));
		return NULL;
	}

	memset (ptd->conns, 0, sizeof (struct memif_connection) * ptd->if_num);

	rv = memif_per_thread_init(&ptd->pt_main, ptd, control_fd_update, APP_NAME, NULL,
				   NULL, NULL);
	if (rv != MEMIF_ERR_SUCCESS) {
		printf ("memif_per_thread_init: %s\n", memif_strerror(rv));
		return NULL;
	}

	socket_filename[strlen(socket_filename)] = '0' + ptd->index;
	strncpy (socket_filename + strlen(socket_filename), ".sock", 5);
	DBG ("socket_filename: %s", socket_filename);

	rv = memif_per_thread_create_socket(ptd->pt_main, &ptd->socket_handle,
					    socket_filename, ptd);
	if (rv != MEMIF_ERR_SUCCESS) {
		printf ("memif_per_thread_create_socket: %s\n", memif_strerror(rv));
		return NULL;
	}

	for (i = 0; i < ptd->if_num; i++) {
		ptd->conns[i].ip_addr[0] = 192;
		ptd->conns[i].ip_addr[0] = 168;
		ptd->conns[i].ip_addr[0] = ptd->index + 1;
		ptd->conns[i].ip_addr[0] = i * 2 + 2;

		memset (&args, 0, sizeof (args));

		args.socket = ptd->socket_handle;
		ptd->conns[i].id = i;
		args.interface_id = i;

		rv = memif_create(&ptd->conns[i].handle, &args, on_connect,
				  on_disconnect, on_interrupt, ptd);
		if (rv < 0) {
			printf ("%s\n", memif_strerror(rv));
			return NULL;
		}
	}

	ptd->pcfd = eventfd(0, EFD_NONBLOCK);
	if (ptd->pcfd < 0) {
		printf ("eventfd: %s\n", strerror(errno));
		return NULL;
	}
	if (add_epoll_fd (ptd->epfd, ptd->pcfd, EPOLLIN) < 0) {
		printf ("Failed to add poll cancel fd to epfd.");
		return NULL;
	}

	ptd->running = true;
	while (ptd->running) {
		rv = poll_event (ptd->pt_main, ptd->pcfd, ptd->epfd, -1);
		if (rv != 0)
			ptd->running = false;
	}

	for (i = 0; i < ptd->if_num; i++)
		memif_delete (&ptd->conns[i].handle);

	memif_delete_socket (&ptd->socket_handle);

	memif_per_thread_cleanup (&ptd->pt_main);

	free (ptd->conns);
	close (ptd->pcfd);

	return NULL;
}

static void
icmpr_print_help ()
{
	printf("exit - Exits the application.\nhelp - Print this help.\nshow - Show memif interfaces\n");
}

static void
icmpr_show_memifs ()
{
	struct icmpr_main *im = &icmpr_main;
	int i, j;
	memif_socket_handle_t sh;

	printf("%u Threads %u Memifs (per thread)\n", im->threads,
		im->per_thread_if_num);
	printf ("=================================\n");



	for (i = 0; i < im->threads; i++) {
		sh = im->ptd[i].socket_handle;
		printf("Thread %u %s\n", i,
			memif_get_socket_filename (sh));
		for (j = 0; j < im->per_thread_if_num; j++) {
			printf("\tMemif id %u\n\t%s\n", im->ptd[i].conns[j].id,
				im->ptd[i].conns[j].connected ? "Link up" : "Link down");
		}
	}
}

int
main (int argc, char **argv)
{
	struct icmpr_main *im = &icmpr_main;
	int rv, i;
	int option_index = 0;
	bool running;
	char buffer[ICMPR_BUFFER_LENGTH];
	uint64_t b = 1;

	memset (im, 0, sizeof (struct icmpr_main));

	im->threads = 4;
	im->per_thread_if_num = 1;

	while ((rv = getopt_long (argc, argv, "t:i:", options, &option_index)) != (-1)) {
		switch (rv) {
			case 't':
				im->threads = strtoul(optarg, NULL, 10);
				break;
			case 'i':
				im->per_thread_if_num = strtoul(optarg, NULL, 10);
				break;
			default:
				break;
		}
	}

	if (im->threads < 1) {
		printf ("threads < 1\n");
		exit(EXIT_FAILURE);
	}

	if (im->per_thread_if_num < 1) {
		printf ("if_num < 1\n");
		exit(EXIT_FAILURE);
	}

	im->ptd = malloc (sizeof (struct per_thread_data) * im->threads);
	if (im->ptd == NULL) {
		printf("%s\n", strerror (errno));
		return -1;
	}
	im->pthread = malloc (sizeof (pthread_t) * im->threads);
	if (im->pthread == NULL) {
		printf("%s\n", strerror (errno));
		return -1;
	}

	for (i = 0; i < im->threads; i++) {
		im->ptd[i].index = i;
		im->ptd[i].if_num = im->per_thread_if_num;
		pthread_create (&im->pthread[i], NULL, icmpr_thread_fn, &im->ptd[i]);
	}

	icmpr_print_help ();

	running = true;
	while (running) {
		printf("cmd: ");
		memset (buffer, 0, ICMPR_BUFFER_LENGTH);
		if (fgets (buffer, ICMPR_BUFFER_LENGTH, stdin) != buffer) {
			printf("%s\n", strerror (errno));
			running = false;
		}

		if (strncmp (buffer, "exit", 4) == 0)
			running = false;
		else if (strncmp (buffer, "help", 4) == 0)
			icmpr_print_help ();
		else if (strncmp (buffer, "show", 4) == 0)
			icmpr_show_memifs ();
	}

	for (i = 0; i < im->threads; i++) {
		rv = write (im->ptd[i].pcfd, &b, sizeof (b));
		if (rv < 0) {
			printf ("Failed to cancel polling. %s\n", strerror (errno));
			exit(EXIT_FAILURE);
		}
		pthread_join (im->pthread[i], NULL);
	}

	free (im->pthread);
	free (im->ptd);

	return 0;
}
