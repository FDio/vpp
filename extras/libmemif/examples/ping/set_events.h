/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef _SET_EVENTS_H_
#define _SET_EVENTS_H_

#include <inttypes.h>
#include <sys/epoll.h>

int add_epoll_fd (int epfd, int fd, uint32_t events);
int del_epoll_fd (int epfd, int fd);
int mod_epoll_fd (int epfd, int fd, uint32_t events);

#endif /* _SET_EVENTS_H_ */
