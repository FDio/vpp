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
