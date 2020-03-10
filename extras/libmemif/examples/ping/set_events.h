#ifndef _SET_EVENTS_H_
#define _SET_EVENTS_H_

#include <inttypes.h>
#include <sys/epoll.h>

int add_epoll_fd (int epfd, int fd, uint32_t events);
int del_epoll_fd (int epfd, int fd);
int mod_epoll_fd (int epfd, int fd, uint32_t events);

#endif /* _SET_EVENTS_H_ */
