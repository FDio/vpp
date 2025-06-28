#ifndef __SCAPY_H__
#define __SCAPY_H__

#include <stddef.h>

int scapy_start();
void scapy_stop();
unsigned char *scapy_build_packet(const char *packet_definition, size_t *packet_len);

#endif /* __SCAPY_H__ */
