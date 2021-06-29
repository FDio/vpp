# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CC = gcc
CFLAGS  = -g -Wall -fPIC
LDFLAGS = -shared -ldl -lrt -fPIC
NAME = vpp_adapter

SRCS = $(NAME).c
OBJS = $(NAME).o
TARGET = $(NAME).so

all: $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS)

$(OBJS):$(SRCS)
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
