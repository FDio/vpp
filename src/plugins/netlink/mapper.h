/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#ifndef MAPPER_H_
#define MAPPER_H_

#include <netlink/netns.h>

/*
 * Automatically map linux network routes to VPP.
 * Each namespace is associated with an individual fib.
 *
 * One linux interface can only be mapped to a single VPP
 * interface, but one VPP interface can be mapped to
 * multiple linux interfaces.
 * A mapped VPP interface must not have any configured fib.
 */

int mapper_add_ns(char *nsname, u32 v4fib_index, u32 v6fib_index, u32 *nsindex);
int mapper_del_ns(u32 nsindex);
int mapper_add_del(u32 nsindex, int linux_ifindex, u32 sw_if_index, int del);

#endif /* MAPPER_H_ */
