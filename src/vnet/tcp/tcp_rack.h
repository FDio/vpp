#ifndef SRC_VNET_TCP_TCP_RACK_H_
#define SRC_VNET_TCP_TCP_RACK_H_

#include <vnet/tcp/tcp.h>

void tcp_rack_init (tcp_connection_t * tc);
void rack_transmit_data (tcp_connection_t * tc, tcp_bt_sample_t * bts);
void rack_retransmit_data (tcp_connection_t * tc, tcp_bt_sample_t * bts);
void rack_update_min_rtt (tcp_connection_t * tc, u32 ack);
void rack_update_state (tcp_connection_t * tc, tcp_bt_sample_t * bts);
u8 rack_detect_reordering (tcp_connection_t * tc, char* file, int line);
void rack_detect_reordering_i (tcp_connection_t * tc, sack_scoreboard_t * sb, tcp_bt_sample_t * bts);
void rack_update_reo_wnd (tcp_connection_t * tc);
void rack_reo_timeout_handler (tcp_connection_t * tc);
int rack_detect_loss_and_arm_timer (tcp_worker_ctx_t * wrk, tcp_connection_t * tc, u32 burst_size);
void rack_update_minrtt_window (tcp_connection_t * tc,f64 rtt);
f64 rack_get_minrtt_from_window(tcp_connection_t * tc);

void tlp_init (tcp_connection_t * tc);
void tlp_schedule_loss_probe (tcp_connection_t * tc);
void tlp_timeout_handler (tcp_connection_t * tc);
void tlp_process_ack (tcp_connection_t * tc, u32 ack);

#endif /* SRC_VNET_TCP_TCP_RACK_H_ */
