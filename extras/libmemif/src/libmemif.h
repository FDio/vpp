/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

/** @file
 *  @defgroup libmemif Example libmemif App
 */

#ifndef _LIBMEMIF_H_
#define _LIBMEMIF_H_

/** Libmemif version. */
#define LIBMEMIF_VERSION "4.0"
/** Default name of application using libmemif. */
#define MEMIF_DEFAULT_APP_NAME "libmemif-app"

#include <inttypes.h>
#include <sys/timerfd.h>
#include <sys/types.h>

/*! Error codes */
typedef enum
{
  MEMIF_ERR_SUCCESS = 0,	/*!< success */
/* SYSCALL ERRORS */
  MEMIF_ERR_SYSCALL,		/*!< other syscall error */
  MEMIF_ERR_CONNREFUSED,	/*!< connection refused */
  MEMIF_ERR_ACCES,		/*!< permission denied */
  MEMIF_ERR_NO_FILE,		/*!< file does not exist */
  MEMIF_ERR_FILE_LIMIT,		/*!< system open file limit */
  MEMIF_ERR_PROC_FILE_LIMIT,	/*!< process open file limit */
  MEMIF_ERR_ALREADY,		/*!< connection already requested */
  MEMIF_ERR_AGAIN,		/*!< fd is not socket, or operation would block */
  MEMIF_ERR_BAD_FD,		/*!< invalid fd */
  MEMIF_ERR_NOMEM,		/*!< out of memory */
/* LIBMEMIF ERRORS */
  MEMIF_ERR_INVAL_ARG,		/*!< invalid argument */
  MEMIF_ERR_NOCONN,		/*!< handle points to no connection */
  MEMIF_ERR_CONN,		/*!< handle points to existing connection */
  MEMIF_ERR_CB_FDUPDATE,	/*!< user defined callback memif_control_fd_update_t error */
  MEMIF_ERR_FILE_NOT_SOCK,	/*!< file specified by socket path
				   exists, but it's not socket */
  MEMIF_ERR_NO_SHMFD,		/*!< missing shm fd */
  MEMIF_ERR_COOKIE,		/*!< wrong cookie on ring */
  MEMIF_ERR_NOBUF_RING,		/*!< ring buffer full */
  MEMIF_ERR_NOBUF,		/*!< not enough memif buffers */
  MEMIF_ERR_NOBUF_DET,		/*!< memif details needs larger buffer */
  MEMIF_ERR_INT_WRITE,		/*!< send interrupt error */
  MEMIF_ERR_MFMSG,		/*!< malformed msg received */
  MEMIF_ERR_QID,		/*!< invalid queue id */
/* MEMIF PROTO ERRORS */
  MEMIF_ERR_PROTO,		/*!< incompatible protocol version */
  MEMIF_ERR_ID,			/*!< unmatched interface id */
  MEMIF_ERR_ACCSLAVE,		/*!< slave cannot accept connection requests */
  MEMIF_ERR_ALRCONN,		/*!< memif is already connected */
  MEMIF_ERR_MODE,		/*!< mode mismatch */
  MEMIF_ERR_SECRET,		/*!< secret mismatch */
  MEMIF_ERR_NOSECRET,		/*!< secret required */
  MEMIF_ERR_MAXREG,		/*!< max region limit reached */
  MEMIF_ERR_MAXRING,		/*!< max ring limit reached */
  MEMIF_ERR_NO_INTFD,		/*!< missing interrupt fd */
  MEMIF_ERR_DISCONNECT,		/*!< disconnect received */
  MEMIF_ERR_DISCONNECTED,	/*!< peer interface disconnected */
  MEMIF_ERR_UNKNOWN_MSG,	/*!< unknown message type */
  MEMIF_ERR_POLL_CANCEL,	/*!< memif_poll_event() was cancelled */
  MEMIF_ERR_MAX_RING,		/*!< too large ring size */
  MEMIF_ERR_PRIVHDR,		/*!< private hdrs not supported */
} memif_err_t;

/**
 * @defgroup MEMIF_FD_EVENT Types of events that need to be watched for specific fd.
 * @ingroup libmemif
 * @{
 */

/** \brief Memif fd events
 * User needs to set events that occurred on fd and pass them to memif_control_fd_handler
 */
typedef enum memif_fd_event_type
{
    MEMIF_FD_EVENT_READ = 1,  /* 00001 */
    MEMIF_FD_EVENT_WRITE = 2, /* 00010 */
    /** inform libmemif that error occurred on fd */
    MEMIF_FD_EVENT_ERROR = 4, /* 00100 */
    /** if set, informs that fd is going to be closed (user may want to stop watching for events on this fd) */
    MEMIF_FD_EVENT_DEL = 8,   /* 01000 */
    /** update events */
    MEMIF_FD_EVENT_MOD = 16   /* 10000 */
} memif_fd_event_type_t;
/** @} */

/** \brief Memif connection handle
    pointer of type void, pointing to internal structure
*/
typedef void *memif_conn_handle_t;

/** \brief Memif socket handle
    pointer of type void, pointing to internal structure
*/
typedef void *memif_socket_handle_t;

/** \brief Memif allocator alloc
    @param size - requested allocation size

    custom memory allocator: alloc function template
*/
typedef void *(memif_alloc_t) (size_t size);


/** \brief Memif realloc
    @param ptr - pointer to memory block
    @param size - requested allocation size

    custom memory reallocation
*/
typedef void *(memif_realloc_t) (void *ptr, size_t size);

/** \brief Memif allocator free
    @param size - requested allocation size

    custom memory allocator: free function template
*/
typedef void (memif_free_t) (void *ptr);

/**
 * @defgroup CALLBACKS Callback functions definitions
 * @ingroup libmemif
 *
 * @{
 */

/** \brief Memif fd event
    @param fd - interrupt file descriptor 
    @param type - memif fd event type
    @param private_ctx - private event data
*/
typedef struct memif_fd_event
{
  int fd;
  memif_fd_event_type_t type;
  void *private_ctx;
} memif_fd_event_t;

/** \brief Memif control file descriptor update (callback function)
    @param fde - memif fd event
    @param private_ctx - private context of socket this fd belongs to


    This callback is called when there is new fd to watch for events on
    or if fd is about to be closed (user mey want to stop watching for events on this fd).
    Private context is taken from libmemif_main, 'private_ctx' passed to memif_per_thread_init()
    or NULL in case of memif_init()
*/
typedef int (memif_control_fd_update_t) (memif_fd_event_t fde,
					 void *private_ctx);

/** \brief Memif connection status update (callback function)
    @param conn - memif connection handle
    @param private_ctx - private context

    Informs user about connection status connected/disconnected.
    On connected -> start watching for events on interrupt fd (optional).
*/
typedef int (memif_connection_update_t) (memif_conn_handle_t conn,
					 void *private_ctx);

/** \brief Memif interrupt occurred (callback function)
    @param conn - memif connection handle
    @param private_ctx - private context
    @param qid - queue id on which interrupt occurred

    Called when event is received on interrupt fd.
*/
typedef int (memif_on_interrupt_t) (memif_conn_handle_t conn, void *private_ctx,
				 uint16_t qid);

/** @} */

/**
 * @defgroup EXTERNAL_REGION External region APIs
 * @ingroup libmemif
 *
 * @{
 */

/** \brief Get external buffer offset (optional)
    @param private_ctx - private context

    Find unallocated external buffer and return its offset.
*/
typedef uint32_t (memif_get_external_buffer_offset_t) (void *private_ctx);

/** \brief Add external region
    @param[out] addr - region address
    @param size - requested region size
    @param fd[out] - file descriptor
    @param private_ctx - private context

    Called by slave. Add external region created by client.
*/
typedef int (memif_add_external_region_t) (void * *addr, uint32_t size,
					   int *fd, void *private_ctx);

/** \brief Get external region address
    @param size - requested region size
    @param fd - file descriptor
    @param private_ctx - private context

    Called by master. Get region address from client.

   \return region address
*/
typedef void *(memif_get_external_region_addr_t) (uint32_t size, int fd,
						  void *private_ctx);

/** \brief Delete external region
    @param addr - region address
    @param size - region size
    @param fd - file descriptor
    @param private_ctx - private context

    Delete external region.
*/
typedef int (memif_del_external_region_t) (void *addr, uint32_t size, int fd,
					   void *private_ctx);

/** \brief Register external region
    @param ar - add external region callback
    @param gr - get external region addr callback
    @param dr - delete external region callback
    @param go - get external buffer offset callback (optional)
*/
void memif_register_external_region (memif_socket_handle_t sock,
                     memif_add_external_region_t * ar,
				     memif_get_external_region_addr_t * gr,
				     memif_del_external_region_t * dr,
				     memif_get_external_buffer_offset_t * go);

/** \brief Register external region
    @param pt_main - per thread main handle
    @param ar - add external region callback
    @param gr - get external region addr callback
    @param dr - delete external region callback
    @param go - get external buffer offset callback (optional)

void memif_per_thread_register_external_region (memif_per_thread_main_handle_t
						pt_main,
						memif_add_external_region_t *
						ar,
						memif_get_external_region_addr_t
						* gr,
						memif_del_external_region_t *
						dr,
						memif_get_external_buffer_offset_t
						* go);

 @} */

/**
 * @defgroup ARGS_N_BUFS Connection arguments and buffers
 * @ingroup libmemif
 *
 * @{
 */

#ifndef _MEMIF_H_
typedef enum
{
  MEMIF_INTERFACE_MODE_ETHERNET = 0,
  MEMIF_INTERFACE_MODE_IP = 1,
  MEMIF_INTERFACE_MODE_PUNT_INJECT = 2,
} memif_interface_mode_t;
#endif /* _MEMIF_H_ */

/** \brief Memif socket arguments
    @param path - UNIX socket path, supports abstract socket (have '\0' or '@' as the first char of the path)
    @param app_name - application name
    @param connection_request_timer - automaticaly request connection each time this timer expires, must be non-zero to enable this feature
    @param on_control_fd_update - if control fd updates inform user to watch new fd
    @param alloc - custom memory allocator, NULL = default
    @param realloc - custom memory reallocation, NULL = default
    @param free - custom memory free, NULL = default

    If param on_control_fd_update is set to NULL,
    libmemif will handle file descriptor event polling
    if a valid callback is set, file descriptor event polling needs to be done by
    user application, all file descriptors and event types will be passed in
    this callback to user application
*/
typedef struct memif_socket_args {
    char path[108];
    char app_name[32];

    struct itimerspec connection_request_timer;

    memif_control_fd_update_t *on_control_fd_update;
    memif_alloc_t *alloc;
    memif_realloc_t *realloc;
    memif_free_t *free;
} memif_socket_args_t;

/** \brief Memif connection arguments
    @param socket - Memif socket handle, if NULL default socket will be used.
		    Default socket is only supported in global database (see memif_init).
		    Custom database does not create a default socket
		    (see memif_per_thread_init).
		    Memif connection is stored in the same database as the socket.
    @param secret - optional parameter used as interface authentication
    @param num_s2m_rings - number of slave to master rings
    @param num_m2s_rings - number of master to slave rings
    @param buffer_size - size of buffer in shared memory
    @param log2_ring_size - logarithm base 2 of ring size
    @param is_master - 0 == master, 1 == slave
    @param interface_id - id used to identify peer connection
    @param interface_name - interface name
    @param mode - 0 == ethernet, 1 == ip , 2 == punt/inject
*/
typedef struct
{
  memif_socket_handle_t socket;	/*!< default = /run/vpp/memif.sock */
  uint8_t secret[24];		/*!< optional (interface authentication) */

  uint8_t num_s2m_rings;	/*!< default = 1 */
  uint8_t num_m2s_rings;	/*!< default = 1 */
  uint16_t buffer_size;		/*!< default = 2048 */
  uint8_t log2_ring_size;	/*!< default = 10 (1024) */
  uint8_t is_master;

  uint32_t interface_id;
  uint8_t interface_name[32];
  memif_interface_mode_t mode:8;
} memif_conn_args_t;

/*! memif receive mode */
typedef enum
{
  MEMIF_RX_MODE_INTERRUPT = 0,	/*!< interrupt mode */
  MEMIF_RX_MODE_POLLING		/*!< polling mode */
} memif_rx_mode_t;

/** \brief Memif buffer
    @param desc_index - ring descriptor index
    @param ring - pointer to ring containing descriptor for this buffer
    @param len - available length
    @param flags - memif buffer flags
    @param data - pointer to shared memory data
*/
typedef struct
{
  uint16_t desc_index;
  void *ring;
  uint32_t len;
/** next buffer present (chained buffers) */
#define MEMIF_BUFFER_FLAG_NEXT (1 << 0)
/** states that buffer is from rx ring */
#define MEMIF_BUFFER_FLAG_RX (1 << 1)
  uint8_t flags;
  void *data;
} memif_buffer_t;
/** @} */

/**
 * @defgroup MEMIF_DETAILS Memif details structs
 * @ingroup libmemif
 *
 * @{
 */

/** \brief Memif queue details
    @param region - region index
    @param qid - queue id
    @param ring_size - size of ring buffer in shared memory
    @param flags - ring flags
    @param head - ring head pointer
    @param tail - ring tail pointer
    @param buffer_size - buffer size on shared memory
*/
typedef struct
{
  uint8_t region;
  uint16_t qid;
  uint32_t ring_size;
/** if set queue is in polling mode, else in interrupt mode */
#define MEMIF_QUEUE_FLAG_POLLING 1
  uint16_t flags;
  uint16_t head;
  uint16_t tail;
  uint16_t buffer_size;
} memif_queue_details_t;

/** \brief Memif region details
    @param index - region index
    @param addr - region address
    @param size - region size
    @param fd - file descriptor
    @param is_external - if not zero then region is defined by client
*/
typedef struct
{
  uint8_t index;
  void *addr;
  uint32_t size;
  int fd;
  uint8_t is_external;
} memif_region_details_t;

/** \brief Memif details
    @param if_name - interface name
    @param inst_name - application name
    @param remote_if_name - peer interface name
    @param remote_inst_name - peer application name
    @param id - connection id
    @param secret - secret
    @param role - 0 = master, 1 = slave
    @param mode - 0 = ethernet, 1 = ip , 2 = punt/inject
    @param socket_path - socket path
    @param regions_num - number of regions
    @param regions - struct containing region details
    @param rx_queues_num - number of receive queues
    @param tx_queues_num - number of transmit queues
    @param rx_queues - struct containing receive queue details
    @param tx_queues - struct containing transmit queue details
    @param error - error string
    @param link_up_down - 1 = up (connected), 2 = down (disconnected)
*/
typedef struct
{
  uint8_t *if_name;
  uint8_t *inst_name;
  uint8_t *remote_if_name;
  uint8_t *remote_inst_name;

  uint32_t id;
  uint8_t *secret;		/* optional */
  uint8_t role;			/* 0 = master, 1 = slave */
  uint8_t mode;			/* 0 = ethernet, 1 = ip, 2 = punt/inject */
  uint8_t *socket_path;
  uint8_t regions_num;
  memif_region_details_t *regions;
  uint8_t rx_queues_num;
  uint8_t tx_queues_num;
  memif_queue_details_t *rx_queues;
  memif_queue_details_t *tx_queues;

  uint8_t *error;
  uint8_t link_up_down;		/* 1 = up, 0 = down */
} memif_details_t;

/** \brief Memif descriptor details
    @param flags - flags
    @param region - index of the buffer region
    @param length - buffer length
    @param offset - buffer offset
    @param metadata - metadata

    Descriptor describes pakcet buffers in the shared memory.
*/
typedef struct memif_desc_details
{
    uint16_t flags;
    uint16_t region;
    uint32_t length;
    uint32_t offset;
    uint32_t metadata;
} memif_desc_details_t;

/** \brief Memif ring details
    @param head - head
    @param tail - tail
    @param flags - flags
    @param offset - offset from beginning of the shared memory
    @param ndesc - number of filled out descriptors
    @param descs - memif buffer descriptors

    Ring represents a ring buffer of descriptors.
*/
typedef struct memif_ring_details
{
    uint16_t head;
    uint16_t tail;
    uint16_t flags;
    void *offset;
    uint16_t ndesc;
    memif_desc_details_t descs[];
} memif_ring_details_t;
/** @} */

/**
 * @defgroup API_CALLS Api calls
 * @ingroup libmemif
 *
 * @{
 */

/** \brief Memif get version

    \return ((MEMIF_VERSION_MAJOR << 8) | MEMIF_VERSION_MINOR)
*/
uint16_t memif_get_version ();

/** \brief Get memif version as string
    \return major.minor
*/
const char * memif_get_version_str ();

/** \brief Memif get queue event file descriptor
    @param conn - memif connection handle
    @param qid - queue id
    @param[out] fd - returns event file descriptor

    \return memif_err_t
*/

int memif_get_queue_efd (memif_conn_handle_t conn, uint16_t qid, int *fd);

/** \brief Memif set rx mode
    @param conn - memif connection handle
    @param rx_mode - receive mode
    @param qid - queue id

    \return memif_err_t
*/
int memif_set_rx_mode (memif_conn_handle_t conn, memif_rx_mode_t rx_mode,
		       uint16_t qid);

/** \brief Memif strerror
    @param err_code - error code

    Converts error code to error message.

    \return Error string
*/
char *memif_strerror (int err_code);

/** \brief Memif get tx ring details
    @param conn - memif connection handle
    @param rd - pointer to memif ring details struct
    @param qid - queue id
    @param ndesc - number of allocated memif_desc_details_t (must be at least equal to ring size)

    Note: don't forget to allocate descs field in memif_ring_details_t to hold all the descriptors.

    \return memif_err_t
*/
int memif_get_tx_ring_details (memif_conn_handle_t conn, memif_ring_details_t * rd, uint16_t qid, uint16_t ndesc);

/** \brief Memif get rx ring details
    @param conn - memif connection handle
    @param rd - pointer to memif ring details struct
    @param qid - queue id
    @param ndesc - number of allocated memif_desc_details_t (must be at least equal to ring size)

    Note: don't forget to allocate descs field in memif_ring_details_t to hold all the descriptors.

    \return memif_err_t
*/
int memif_get_rx_ring_details (memif_conn_handle_t conn, memif_ring_details_t * rd, uint16_t qid, uint16_t ndesc);

/** \brief Memif get details
    @param conn - memif connection handle
    @param md - pointer to memif details struct
    @param buf - buffer containing details strings
    @param buflen - length of buffer

    \return memif_err_t
*/
int memif_get_details (memif_conn_handle_t conn, memif_details_t * md,
		       char *buf, ssize_t buflen);

/** \brief Memory interface create function
    @param conn - connection handle for client app
    @param args - memory interface connection arguments
    @param on_connect - inform user about connected status
    @param on_disconnect - inform user about disconnected status
    @param on_interrupt - informs user about interrupt, if set to null user will not be notified about interrupt, user can use memif_get_queue_efd call to get interrupt fd to poll for events
    @param private_ctx - private context passed back to user with callback

    Creates memory interface.

    SLAVE-MODE -
        Start timer that will send events to timerfd. If this fd is passed to memif_control_fd_handler
        every disconnected memif in slave mode will send connection request.
        On success new fd is passed to user with memif_control_fd_update_t.

    MASTER-MODE -
        Create listener socket and pass fd to user with memif_control_fd_update_t.
        If this fd is passed to memif_control_fd_handler accept will be called and
        new fd will be passed to user with memif_control_fd_update_t.


    \return memif_err_t
*/
int memif_create (memif_conn_handle_t * conn, memif_conn_args_t * args,
		  memif_connection_update_t * on_connect,
		  memif_connection_update_t * on_disconnect,
		  memif_on_interrupt_t * on_interrupt, void *private_ctx);

/** \brief Memif control file descriptor handler
    @param ptr - pointer to event data
    @param events - event type(s) that occurred

    \return memif_err_t

*/
int memif_control_fd_handler (void *ptr, memif_fd_event_type_t events);

/** \brief Memif delete
    @param conn - pointer to memif connection handle


    disconnect session (free queues and regions, close file descriptors, unmap shared memory)
    set connection handle to NULL, to avoid possible double free

    \return memif_err_t
*/
int memif_delete (memif_conn_handle_t * conn);

/** \brief Memif buffer enq tx
    @param conn - memif connection handle
    @param qid - number identifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to enqueue
    @param count_out - returns number of allocated buffers

    Slave is producer of buffers.
    If connection handle points to master returns MEMIF_ERR_INVAL_ARG.

    \return memif_err_t
*/
int memif_buffer_enq_tx (memif_conn_handle_t conn, uint16_t qid,
			 memif_buffer_t * bufs, uint16_t count,
			 uint16_t * count_out);

/** \brief Memif buffer alloc
    @param conn - memif connection handle
    @param qid - number identifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to allocate
    @param count_out - returns number of allocated buffers
    @param size - buffer size, may return chained buffers if size > buffer_size

    \return memif_err_t
*/
int memif_buffer_alloc (memif_conn_handle_t conn, uint16_t qid,
			memif_buffer_t * bufs, uint16_t count,
			uint16_t * count_out, uint16_t size);

/** \brief Memif refill ring
    @param conn - memif connection handle
    @param qid - number identifying queue
    @param count - number of buffers to be placed on ring
    @param headroom - offset the buffer by headroom

    \return memif_err_t
*/
int memif_refill_queue (memif_conn_handle_t conn, uint16_t qid,
			uint16_t count, uint16_t headroom);

/** \brief Memif transmit buffer burst
    @param conn - memif connection handle
    @param qid - number identifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to transmit
    @param tx - returns number of transmitted buffers

    \return memif_err_t
*/
int memif_tx_burst (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count, uint16_t * tx);

/** \brief Memif receive buffer burst
    @param conn - memif connection handle
    @param qid - number identifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to receive
    @param rx - returns number of received buffers

    Consume interrupt event for receive queue.
    The event is not consumed, if memif_rx_burst fails.

    \return memif_err_t
*/
int memif_rx_burst (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count, uint16_t * rx);

/** \brief Memif poll event
    @param sock - socket to poll events on
    @param timeout - timeout in seconds

    Passive event polling -
    timeout = 0 - dont wait for event, check event queue if there is an event and return.
    timeout = -1 - wait until event
 
    \return memif_err_t
*/
int memif_poll_event (memif_socket_handle_t sock, int timeout);

/** \brief Send signal to stop concurrently running memif_poll_event().
    @param sock - stop polling on this socket

    The function, however, does not wait for memif_poll_event() to stop.
    memif_poll_event() may still return simply because an event has occurred
    or the timeout has elapsed, but if called repeatedly in an infinite loop,
    a canceled memif_poll_event() is guaranteed to return MEMIF_ERR_POLL_CANCEL
    in the shortest possible time.
    This feature was not available in the first release.
    Use macro MEMIF_HAVE_CANCEL_POLL_EVENT to check if the feature is present.

    \return memif_err_t
*/
#define MEMIF_HAVE_CANCEL_POLL_EVENT 1
int memif_cancel_poll_event (memif_socket_handle_t sock);

/** \brief Send connection request
    @param conn - memif connection handle

    Only slave interface can request connection.

    \return memif_err_t
*/
int memif_request_connection (memif_conn_handle_t conn);

/** \brief Create memif socket
    @param sock - socket handle for client app
    @param args - memif socket arguments
    @param private_ctx - private context

    The first time an interface is assigned a socket, its type is determined.
    For master role it's 'listener', for slave role it's 'client'. Each interface
    requires socket of its respective type. Default socket is created if no
    socket handle is passed to memif_create(). It's private context is NULL.
    If all interfaces using this socket are deleted, the socket returns
    to its default state.

    \return memif_err_t
*/
int memif_create_socket (memif_socket_handle_t * sock, memif_socket_args_t * args, void * private_ctx);

/** \brief Get memif socket handle from connection
    @param conn - memif connection handle

    \return memif_socket_handle_t
*/
memif_socket_handle_t memif_get_socket_handle(memif_conn_handle_t conn);

/** \brief Delete memif socket
    @param sock - socket handle for client app

    When trying to free socket in use, socket will not be freed and
    MEMIF_ERR_INVAL_ARG is returned.

    \return memif_err_t
*/
int memif_delete_socket (memif_socket_handle_t * sock);

/** \brief Get socket path
    @param sock - socket handle for client app

    Return constant pointer to socket path.

    \return const char *
*/
const char *memif_get_socket_path (memif_socket_handle_t sock);

/** \brief Get listener file descriptor
    @param sock - memif socket handle

    \return listener fd
*/
int memif_get_listener_fd (memif_socket_handle_t sock);

/** \brief Set listener file descriptor
    @param sock - memif socket handle
    @param if - file descriptor

    \return memif_err_t
*/
int memif_set_listener_fd (memif_socket_handle_t sock, int fd);

/** \brief Set connection request timer value
    @param sock - memif socket handle
    @param timer - new timer value

    Timer on which all disconnected slaves request connection.
    If the timer doesn't exist (timerspec is 0) create new timer.
    See system call 'timer_settime' man-page.
    \return memif_err_t
*/
int memif_set_connection_request_timer (memif_socket_handle_t sock, struct itimerspec timer);

/** @} */

#endif /* _LIBMEMIF_H_ */