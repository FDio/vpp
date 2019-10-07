A modest proposal to VPP API incompatibility problem.


Problem statement

Currently, with any VPP API change that alters the CRC of a message, any downstream consumer using that API,
needs to perform the following ritual:

1) implement the changes required to match the VPP side
2) perform a *synchronous* update of the VPP code and the control plane code


Current State Of The Art

In the today's process we perform "API freeze" (F0), and shortly after that fork a branch stable/DDDD, which has all the APIs
frozen. This effectively locks the consumers into stable/DDDD branch - a growing difference between the APIs between that branch
and master makes it impossible to swap out the VPP code alone - a full upgrade is required.

While for some scenarios (like networking-vpp) it merely decreases the servicability and blocks them
from trialing the latest code on the master branch, for some of the consumers that *must* stay on the latest
master branch (CSIT) it doesn't bring much benefit at all.

As a result, the "CRC job" and the associated process have been put in place,
in an effort to highlight and partially mitigate this problem.
Note, that for the latter case, because "VPP" and "Testing infra" are in two different repositories, even perfectly
synchronous execution of the dance results in some dead time and requirement for the manual labour.

This proposal aims to remove the "flag day" requirement on the VPP side, which would subsequently open the doors to removing
the "flag day" on the client side as well.

The second approach sometimes used is addition of *foo_v2*, *foo_v3* messages. That avoids breaking the existing clients,
but the resulting lifecycle of the messages must be managed manually and since the "vX" part of the name remains there forever,
it is rather confusing.

Elevator Pitch

At "API freeze" (F0) date, generate an identity translation layer within the VPP C handler code. Any subsequent API changes
MUST be accompanied with the corresponding modification of the translation layer required to maintain the compatibility.

This translation layer function is composable - thus at the release N+1 another translation layer can be inserted at the bottom
of the chain, and at some point the topmost translation layer can be deleted, thus deprecating the corresponding API calls.

The translation layer can implement counters/warnings/etc. to catch the obsolete operations in testing, in order to facilitate
the transition for the downstream clients.

The Details

First, a little background into how the API handling is implemented in VPP. The primary source of truth is the .api files,
containing the data types of the messages exchanged in the API calls.

For each API call *foobar*, there is an automatically generated *vl_api_foobar_t* C type, corresponding to the message layout
in shared memory during the call, and the convention is to have the *vl_api_foobar_t_handler* function, taking a single argument
of that type as a parameter. The VPPAPIGEN infrastructure also calculates the CRC of the message type (say *0xdeadbeef*), and stores that CRC alongside the name in the initialization routines.

At runtime, a component requests a range of message IDs corresponding to the messages it wants to implement, and registers
the handler for a string *foobar_deadbeef* and the message ID of start of the range + the enum value of that message within
the component's space.

Thus, the approximate code is as follows:

static void vl_api_foobar_t_handler(vl_api_foobar_t *mp)
{
  vl_api_foobar_reply_t *rmp;
  int rv;
  int return_result_1 = 0;

  /* extract the data from mp and call the internal handler function */
  rv = foobar_internal_handler_function(mp->one, mp->two, mp->three, &return_result_1);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_FOOBAR_REPLY,
  ({
    rmp->return_result_1 = htonl(return_result_1);
  }));
  /* *INDENT-ON* */
}



#define REPLY_MACRO2(t, body)                                           \
do {                                                                    \
    vl_api_registration_t *rp;                                          \
    rv = vl_msg_api_pd_handler (mp, rv);                                \
    rp = vl_api_client_index_to_registration (mp->client_index);        \
    if (rp == 0)                                                        \
      return;                                                           \
                                                                        \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                             \
    rmp->_vl_msg_id = htons((t)+(REPLY_MSG_ID_BASE));                   \
    rmp->context = mp->context;                                         \
    rmp->retval = ntohl(rv);                                            \
    do {body;} while (0);                                               \
    vl_api_send_msg (rp, (u8 *)rmp);                                    \
} while(0);

// vl_api_memclnt_create_internal

 svm_queue_t *q;
 q = clib_mem_alloc (sizeof (*q));
  api_index = vl_api_memclnt_create_internal ("vpp_compat_1908", q);

static void
api_acl_send_control_ping(vat_main_t *vam)
{
  vl_api_acl_plugin_control_ping_t *mp_ping;

  M(ACL_PLUGIN_CONTROL_PING, mp_ping);
  S(mp_ping);
}



The translation layer at the time of the F0 for this function will be automatically generated and will look as follows:

```
static void vl_api_foobar_deadbeef_t_handler(vl_api_foobar_deadbeef_t *mp)
{
  vl_api_foobar_reply_deadbeef_t *rmp;
  vl_api_registration_t *rp;                                     
  int rv;

  vl_api_foobar_t mp0;
  vl_api_foobar_reply_t *rmp0;

  int msglen = vl_msg_api_get_msg_length(mp);

  mp0 = vl_msg_api_alloc(vl_msg_api_get_msg_length (mp));
  
  memcpy_fast(mp0, mp, msglen);

  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & cert_mp);

  vl_api_foobar_t_handler(&mp0);

  /* the queue now has 1..N messages with the reply */
  rp = vl_api_client_index_to_registration (mp->client_index);     

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons(__FIXME__REPLY_MSG_ID);
  rmp->context = mp->context;
  rmp->retval = rmp0->retval;

  vl_api_send_msg (rp, (u8 *)rmp);

}


```







