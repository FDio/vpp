#ifndef _PARSER_H_
#define _PARSER_H_

#include <libmemif.h>
#include "common.h"

void assign_unique_id (memif_connection_t * c, int idx_max);
int bad_params (memif_connection_t * c, char **err_msg);
int set_affinity_cpu (char *saveptr1, char **err_msg);
int set_arg_conn (memif_connection_t * c, char *saveptr1, char **err_msg);
int parse_arg (char argv[], char **err_msg);
int valid_ping (char *arg, uint8_t ip_ping[4], int *ping_index,
		int *ping_qid);

#endif /* _PARSER_H_ */
