#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <apicompat/apicompat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include "foobar.h"
#include "foobar_upcall.h"

u16 vl_api_acl_add_replace_13bc8539_upcall_id = 0;

static inline void *
vl_api_acl_add_replace_13bc8539_t_print (vl_api_acl_add_replace_13bc8539_t *mp, void *handle)
{
	/* this should be the copy of the current code in the untagged print function */
	vlib_cli_output(handle, "vl_api_acl_add_replace_13bc8539_t_print called\n");

	return handle;
}


static void **msg_vec = 0;

static void
vl_api_acl_add_replace_13bc8539_t_handler (vl_api_acl_add_replace_13bc8539_t *mp)
{
  vl_api_acl_add_replace_reply_ac407b0c_t *rmp;
  vl_api_registration_t *rp;
  apicompat_main_t *amp = &apicompat_main;
  // int rv;

  vl_api_acl_add_replace_t *mp0;
  // vl_api_acl_add_replace_reply_t *rmp0;

  int msglen = vl_msg_api_get_msg_length(mp);

  mp0 = vl_msg_api_alloc(vl_msg_api_get_msg_length (mp));

  clib_memcpy_fast(mp0, mp, msglen);
  mp0->_vl_msg_id = htons(vl_api_acl_add_replace_13bc8539_upcall_id);

  apicompat_send_and_handle(amp, (u8 *) mp0);

  /// vl_api_acl_add_replace_t_handler(&mp0);

  /* the queue now has 1..N messages with the reply */

  void *msg = 0;
  rp = vl_api_client_index_to_registration (mp->client_index);
  while (apicompat_get_message(amp, &msg))
    {
      u16 id = clib_net_to_host_u16 (*((u16 *) msg));
      clib_warning ("compat layer got message: %d", id);
      // vl_msg_api_free ((void *) msg);
      vec_add1(msg_vec, msg);
    }

  void **msg_v;

  /* now send all these messages */
  vec_foreach(msg_v, msg_vec) {
      vl_api_send_msg (rp, *msg_v);
  }
  _vec_len(msg_vec) = 0;


  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons(42); // __FIXME__REPLY_MSG_ID);
  rmp->context = mp->context;
  // rmp->retval = rmp0->retval;

  vl_api_send_msg (rp, (u8 *)rmp);

}

extern void register_legacy_message_and_crc(char *name_and_crc, void *action_handler, void *print_handler);

void
foobar_register(void) {
	vl_api_acl_add_replace_13bc8539_upcall_id = vl_msg_api_get_msg_index((u8 *)"acl_add_replace_cae6107c");
	// acl_add_replace_reply, ac407b0c
	register_legacy_message_and_crc("acl_add_replace_13bc8539", vl_api_acl_add_replace_13bc8539_t_handler, vl_api_acl_add_replace_13bc8539_t_print);
}
