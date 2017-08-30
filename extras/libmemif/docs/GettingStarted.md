## Getting started

#### Concept (Connecting to VPP)

For detailed information on api calls and structures please refer to [libmemif.h](../src/libmemif.h)

1. Initialize memif
   - Declare callback function handling file descriptor event polling.
```C
int
control_fd_update (int fd, uint8_t events)
{
...
}
```
   - Call memif initialization function. memif\_init
```C
err = memif_init (control_fd_update, APP_NAME);
```
   
> If event occurres on any file descriptor returned by this callback, call memif\_control\_fd\_handler function.
```C
memif_err = memif_control_fd_handler (evt.data.fd, events);
``` 
> If callback function parameter for memif\_init function is set to NULL, libmemif will handle file descriptor event polling.
  Api call memif\_poll\_event will call epoll\_pwait with user defined timeout to poll event on file descriptors opened by libmemif.
```C
/* main loop */
    while (1)
    {
        if (memif_poll_event (-1) < 0)
        {
            DBG ("poll_event error!");
        }
    }
```
    
> Memif initialization function will initialize internal structures and create timer file descriptor, which will be used for sending periodic connection requests. Timer is disarmed if no memif interface is created.
 
2. Creating interface
   - Declare memif connction handle.
```C
memif_conn_handle_t c;
```
> example app uses struct that contains connection handle, rx/tx buffers and other connection specific information.

   - Specify connection arguments.
```C
memif_conn_args_t args;
memset (&args, 0, sizeof (args));
args.is_master = is_master;
args.log2_ring_size = 10;
args.buffer_size = 2048;
args.num_s2m_rings = 2;
args.num_m2s_rings = 2;
strncpy ((char *) args.interface_name, IF_NAME, strlen (IF_NAME));
strncpy ((char *) args.instance_name, APP_NAME, strlen (APP_NAME));
args.mode = 0;
args.interface_id = 0;
```
   - Declare callback functions called on connected/disconnected/interrupted status changed.
```C
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
...
}

int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
    INFO ("memif connected!");
    return 0;
}
```
   - Call memif interface create function. memif\_create
```C
err = memif_create (&c->conn,
        &args, on_connect, on_disconnect, on_interrupt, &ctx[index]);
```
> If connection is in slave mode, arms timer file descriptor.
> If on interrupt callback is set to NULL, user will not be notified about interrupt. Use memif\_get\_queue\_efd call to get interrupt file descriptor for specific queue.
```C
int fd = -1;
err = memif_get_queue_efd (c->conn, data->qid, &fd);
```

3. Connection establishment
    - User application will poll events on all file descriptors returned in memif\_control\_fd\_update\_t callback.
    - On event call memif\_control\_fd\_handler.
    - Everything else regarding connection establishment will be done internally.
    - Once connection has been established, a callback will inform the user about connection status change.

4. Interrupt packet receive
    - If event is polled on interrupt file descriptor, libmemif will call memif\_interrupt\_t callback specified for every connection instance.
```C
int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
...
}
```

6. Memif buffers
    - Packet data are stored in memif\_buffer\_t. Pointer _data_ points to shared memory buffer, and unsigned integer *data\_len* contains packet data length.
```C
typedef struct
{
    uint16_t desc_index;
    uint32_t buffer_len;
    uint32_t data_len;
    void *data;
} memif_buffer_t;
```

5. Packet receive
    - Api call memif\_rx\_burst will set all required fields in memif buffers provided by user application.
```C
err = memif_rx_burst (c->conn, qid, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
```
    - User application can then process packets.
    - Api call memif\_buffer\_free will make supplied memif buffers ready for next receive and mark shared memory buffers as free.
```C
err = memif_buffer_free (c->conn, qid, c->rx_bufs, rx, &fb);
```

6. Packet transmit
    - Api call memif\_buffer\_alloc will set all required fields in memif buffers provided by user application.
```C
err = memif_buffer_alloc (c->conn, qid, c->tx_bufs, n, &r);
```
    - User application can populate shared memory buffers with packets.
    - Api call memif\_tx\_burst will inform peer interface (master memif on VPP) that there are packets ready to receive and mark memif buffers as free.
```C
err = memif_tx_burst (c->conn, qid, c->tx_bufs, c->tx_buf_num, &r);
```

7. Helper functions
    - Memif details
      - Api call memif\_get\_details will return details about connection.
```C
err = memif_get_details (c->conn, &md, buf, buflen);
```
    - Memif error messages
      - Every api call returns error code (integer value) mapped to error string.
      - Call memif\_strerror will return error message assigned to specific error code.
```C
if (err != MEMIF_ERR_SUCCESS)
    INFO ("memif_get_details: %s", memif_strerror (err));
```
        - Not all syscall errors are translated to memif error codes. If error code 1 (MEMIF\_ERR\_SYSCALL) is returned then libmemif needs to be compiled with -DMEMIF_DBG flag to print error message. Use _make -B_ to rebuild libmemif in debug mode.

#### Example app (libmemif fd event polling):

- [ICMP Responder](../examples/icmp_responder/main.c)
> Optional argument: transmit queue id.
```
icmpr 1
```
> Set transmit queue id to 1. Default is 0.
> Application will create memif interface in slave mode and try to connect to VPP. Exit using Ctrl+C. Application will handle SIGINT signal, free allocated memory and exit with EXIT_SUCCESS.

#### Example app:

- [ICMP Responder custom fd event polling](../examples/icmp_responder-epoll/main.c)

#### Example app (multi-thread queue polling)

- [ICMP Responder multi-thread](../examples/icmp_responder-mt/main.c)

> Simple example of libmemif multi-thread usage. Connection establishment is handled by main thread. There are two rx queues in this example. One in polling mode and second in interrupt mode.

VPP config:
```
# create memif id 0 master
# set int state memif0 up
# set int ip address memif0 192.168.1.1/24
# ping 192.168.1.2
```
For multiple rings (queues) support run VPP with worker threads:
example startup.conf:
```
unix {
  interactive
  nodaemon 
  full-coredump
}

cpu {
  workers 2
}
```
VPP config:
```
# create memif id 0 master
# set int state memif0 up
# set int ip address memif0 192.168.1.1/24
# ping 192.168.1.2
```
> Master mode queue number is limited by worker threads. Slave mode interface needs to specify number of queues.
```
# create memif id 0 slave rx-queues 2 tx-queues 2
```
> Example applications use VPP default socket file for memif: /run/vpp/memif.sock
> For master mode, socket directory must exist prior to memif\_create call.

#### Unit tests

Unit tests use [Check](https://libcheck.github.io/check/index.html) framework. This framework must be installed in order to build *unit\_test* binary.
Ubuntu/Debian:
```
sudo apt-get install check
```
[More platforms](https://libcheck.github.io/check/web/install.html)

