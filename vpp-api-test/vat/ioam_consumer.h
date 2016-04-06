#ifndef __included_ioam_consumer_h__
#define __included_ioam_consumer_h__
typedef enum ioam_notification_event_ {
  IOAM_EVENT_FLOW_RECORD,
  IOAM_EVENT_SCV_FAIL,
  IOAM_EVENT_PPC_STATS,
  IOAM_EVENT_MAX
} IOAM_EVENT;
typedef void (*ioam_data_callback_t) (IOAM_EVENT event,void * mp, int msg_length, void *data);
extern ioam_data_callback_t ioam_cb_active;
extern void *cb_user_data;

#endif
