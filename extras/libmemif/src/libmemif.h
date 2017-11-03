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

/** @file */

#ifndef _LIBMEMIF_H_
#define _LIBMEMIF_H_

/** Libmemif version. */
#define LIBMEMIF_VERSION "1.0"
/** Default name of application using libmemif. */
#define MEMIF_DEFAULT_APP_NAME "libmemif-app"

#include <inttypes.h>

#include <memif.h>

/*! Error codes */
typedef enum
{
  MEMIF_ERR_SUCCESS = 0,	/*!< success */
/* SYSCALL ERRORS */
  MEMIF_ERR_SYSCALL,		/*!< other syscall error */
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
  MEMIF_ERR_FILE_NOT_SOCK,	/*!< file specified by socket filename 
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
  MEMIF_ERR_DISCONNECT,		/*!< disconenct received */
  MEMIF_ERR_DISCONNECTED,	/*!< peer interface disconnected */
  MEMIF_ERR_UNKNOWN_MSG,	/*!< unknown message type */
  MEMIF_ERR_POLL_CANCEL,	/*!< memif_poll_event() was cancelled */
  MEMIF_ERR_MAX_RING,		/*!< too large ring size */
} memif_err_t;

/**
 * @defgroup MEMIF_FD_EVENT Types of events that need to be watched for specific fd.
 *
 * @{
 */

/** user needs to set events that occured on fd and pass them to memif_control_fd_handler */
#define MEMIF_FD_EVENT_READ  (1 << 0)
#define MEMIF_FD_EVENT_WRITE (1 << 1)
/** inform libmemif that error occured on fd */
#define MEMIF_FD_EVENT_ERROR (1 << 2)
/** if set, informs that fd is going to be closed (user may want to stop watching for events on this fd) */
#define MEMIF_FD_EVENT_DEL   (1 << 3)
/** update events */
#define MEMIF_FD_EVENT_MOD   (1 << 4)
/** @} */

/** *brief Memif connection handle
    pointer of type void, pointing to internal structure
*/
typedef void *memif_conn_handle_t;
/**
 * @defgroup CALLBACKS Callback functions definitions
 *
 * @{
 */

/** \brief Memif control file descriptor update (callback function)
    @param fd - new file descriptor to watch
    @param events - event type(s) to watch for

    This callback is called when there is new fd to watch for events on
    or if fd is about to be closed (user mey want to stop watching for events on this fd).
*/
typedef int (memif_control_fd_update_t) (int fd, uint8_t events);

/** \brief Memif connection status update (callback function)
    @param conn - memif connection handle
    @param private_ctx - private context

    Informs user about connection status connected/disconnected.
    On connected -> start watching for events on interrupt fd (optional).
*/
typedef int (memif_connection_update_t) (memif_conn_handle_t conn,
					 void *private_ctx);

/** \brief Memif interrupt occured (callback function)
    @param conn - memif connection handle
    @param private_ctx - private context
    @param qid - queue id on which interrupt occured

    Called when event is received on interrupt fd.
*/
typedef int (memif_interrupt_t) (memif_conn_handle_t conn, void *private_ctx,
				 uint16_t qid);
/** @} */

/**
 * @defgroup ARGS_N_BUFS Connection arguments and buffers
 *
 * @{
 */

/** \brief Memif connection arguments
    @param socket_filename - socket filename
    @param secret - otional parameter used as interface autenthication
    @param num_s2m_rings - number of slave to master rings
    @param num_m2s_rings - number of master to slave rings
    @param buffer_size - size of buffer in shared memory
    @param log2_ring_size - logarithm base 2 of ring size
    @param is_master - 0 == master, 1 == slave
    @param interface_id - id used to identify peer connection
    @param interface_name - interface name
    @param instance_name - application name
    @param mode - 0 == ethernet, 1 == ip , 2 == punt/inject
*/
typedef struct
{
  uint8_t *socket_filename;	/*!< default = /run/vpp/memif.sock */
  uint8_t secret[24];		/*!< optional (interface authentication) */

  uint8_t num_s2m_rings;	/*!< default = 1 */
  uint8_t num_m2s_rings;	/*!< default = 1 */
  uint16_t buffer_size;		/*!< default = 2048 */
  memif_log2_ring_size_t log2_ring_size;	/*!< default = 10 (1024) */
  uint8_t is_master;

  memif_interface_id_t interface_id;
  uint8_t interface_name[32];
  uint8_t instance_name[32];
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
    @param buffer_len - shared meory buffer length
    @param data_len - data length
    @param data - pointer to shared memory data
*/
typedef struct
{
  uint16_t desc_index;
  uint32_t buffer_len;
  uint32_t data_len;
  void *data;
} memif_buffer_t;
/** @} */

/**
 * @defgroup MEMIF_DETAILS Memif details structs
 *
 * @{
 */

/** \brief Memif queue details
    @param qid - queue id
    @param ring_size - size of ring buffer in sharem memory
    @param buffer_size - buffer size on sharem memory
*/
typedef struct
{
  uint8_t qid;
  uint32_t ring_size;
  uint16_t buffer_size;
  /* add ring information */
} memif_queue_details_t;

/** \brief Memif details
    @param if_name - interface name
    @param inst_name - application name
    @param remote_if_name - peer interface name
    @param remote_inst_name - peer application name
    @param id - connection id
    @param secret - secret
    @param role - 0 = master, 1 = slave
    @param mode - 0 = ethernet, 1 = ip , 2 = punt/inject
    @param socket_filename = socket filename
    @param rx_queues_num - number of receive queues
    @param tx_queues_num - number of transmit queues
    @param rx_queues - struct containing receive queue details
    @param tx_queues - struct containing transmit queue details
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
  uint8_t *socket_filename;
  uint8_t rx_queues_num;
  uint8_t tx_queues_num;
  memif_queue_details_t *rx_queues;
  memif_queue_details_t *tx_queues;

  uint8_t link_up_down;		/* 1 = up, 0 = down */
} memif_details_t;
/** @} */

/**
 * @defgroup API_CALLS Api calls
 *
 * @{
 */

/** \biref Memif get queue event file descriptor
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

/** \brief Memif get details
    @param conn - memif conenction handle
    @param md - pointer to memif details struct
    @param buf - buffer containing details strings
    @param buflen - length of buffer

    \return memif_err_t
*/
int memif_get_details (memif_conn_handle_t conn, memif_details_t * md,
		       char *buf, ssize_t buflen);

/** \brief Memif initialization
    @param on_control_fd_update - if control fd updates inform user to watch new fd
    @param app_name - application name

    if param on_control_fd_update is set to NULL,
    libmemif will handle file descriptor event polling
    if a valid callback is set, file descriptor event polling needs to be done by
    user application, all file descriptors and event types will be passed in
    this callback to user application

    Initialize internal libmemif structures. Create timerfd (used to periodically request connection by
    disconnected memifs in slave mode, with no additional API call). This fd is passed to user with memif_control_fd_update_t
    timer is inactive at this state. It activates with if there is at least one memif in slave mode.

    \return memif_err_t
*/
int memif_init (memif_control_fd_update_t * on_control_fd_update,
		char *app_name);

/** \brief Memif cleanup

    Free libmemif internal allocations.

    \return 0
*/
int memif_cleanup ();

/** \brief Memory interface create function
    @param conn - connection handle for user app
    @param args - memory interface connection arguments
    @param on_connect - inform user about connected status
    @param on_disconnect - inform user about disconnected status
    @param on_interrupt - informs user about interrupt, if set to null user will not be notified about interrupt, user can use memif_get_queue_efd call to get interrupt fd to poll for events
    @param private_ctx - private contex passed back to user with callback

    Creates memory interface.
     
    SLAVE-MODE - 
        Start timer that will send events to timerfd. If this fd is passed to memif_control_fd_handler
        every disconnected memif in slave mode will send connection request.
        On success new fd is passed to user with memif_control_fd_update_t.

    MASTER-MODE - 
        Create listener socket and pass fd to user with memif_cntrol_fd_update_t.
        If this fd is passed to memif_control_fd_handler accept will be called and
        new fd will be passed to user with memif_control_fd_update_t.


    \return memif_err_t
*/
int memif_create (memif_conn_handle_t * conn, memif_conn_args_t * args,
		  memif_connection_update_t * on_connect,
		  memif_connection_update_t * on_disconnect,
		  memif_interrupt_t * on_interrupt, void *private_ctx);

/** \brief Memif control file descriptor handler
    @param fd - file descriptor on which the event occured
    @param events - event type(s) that occured

    If event occures on any control fd, call memif_control_fd_handler.
    Internal - lib will "identify" fd (timerfd, lsitener, control) and handle event accordingly.
 
    FD-TYPE - 
        TIMERFD - 
            Every disconnected memif in slave mode will request connection.
        LISTENER or CONTROL - 
            Handle socket messaging (internal connection establishment).
        INTERRUPT - 
            Call on_interrupt callback (if set).
        
    \return memif_err_t

*/
int memif_control_fd_handler (int fd, uint8_t events);

/** \brief Memif delete
    @param conn - pointer to memif connection handle


    disconnect session (free queues and regions, close file descriptors, unmap shared memory)
    set connection handle to NULL, to avoid possible double free

    \return memif_err_t
*/
int memif_delete (memif_conn_handle_t * conn);

/** \brief Memif buffer alloc
    @param conn - memif conenction handle
    @param qid - number indentifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to allocate
    @param count_out - returns number of allocated buffers
    @param size - minimal buffer size, 0 = standard buffer size

    \return memif_err_t
*/
int memif_buffer_alloc (memif_conn_handle_t conn, uint16_t qid,
			memif_buffer_t * bufs, uint16_t count,
			uint16_t * count_out, uint16_t size);

/** \brief Memif buffer free
    @param conn - memif conenction handle
    @param qid - number indentifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to free
    @param count_out - returns number of freed buffers

    \return memif_err_t
*/
int memif_buffer_free (memif_conn_handle_t conn, uint16_t qid,
		       memif_buffer_t * bufs, uint16_t count,
		       uint16_t * count_out);

/** \brief Memif transmit buffer burst
    @param conn - memif conenction handle
    @param qid - number indentifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to transmit
    @param tx - returns number of transmitted buffers

    \return memif_err_t
*/
int memif_tx_burst (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count, uint16_t * tx);

/** \brief Memif receive buffer burst
    @param conn - memif conenction handle
    @param qid - number indentifying queue
    @param bufs - memif buffers
    @param count - number of memif buffers to receive
    @param rx - returns number of received buffers

    \return memif_err_t
*/
int memif_rx_burst (memif_conn_handle_t conn, uint16_t qid,
		    memif_buffer_t * bufs, uint16_t count, uint16_t * rx);

/** \brief Memif poll event
    @param timeout - timeout in seconds

    Passive event polling - 
    timeout = 0 - dont wait for event, check event queue if there is an event and return.
    timeout = -1 - wait until event

    \return memif_err_t
*/
int memif_poll_event (int timeout);

/** \brief Send signal to stop concurrently running memif_poll_event().

    The function, however, does not wait for memif_poll_event() to stop.
    memif_poll_event() may still return simply because an event has occured
    or the timeout has elapsed, but if called repeatedly in an infinite loop,
    a canceled memif_poll_event() is guaranted to return MEMIF_ERR_POLL_CANCEL
    in the shortest possible time.
    This feature was not available in the first release.
    Use macro MEMIF_HAVE_CANCEL_POLL_EVENT to check if the feature is present.

    \return memif_err_t
*/
#define MEMIF_HAVE_CANCEL_POLL_EVENT 1
int memif_cancel_poll_event ();
/** @} */

#endif /* _LIBMEMIF_H_ */
