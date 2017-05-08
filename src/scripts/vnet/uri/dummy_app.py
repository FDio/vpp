#!/usr/bin/env python

import socket
import sys
import time

# action can be reflect or drop 
action = "drop"
test = 0

def test_data (data, n_rcvd):
    n_read = len (data);
    for i in range(n_read):
        expected = (n_rcvd + i) & 0xff
        byte_got = ord (data[i])
        if (byte_got != expected):
            print("Difference at byte {}. Expected {} got {}"
                  .format(n_rcvd + i, expected, byte_got))
    return n_read

def handle_connection (connection, client_address):
    print("Received connection from {}".format(repr(client_address)))
    n_rcvd = 0
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break;
            if (test == 1):
                n_rcvd += test_data (data, n_rcvd)
            if (action != "drop"):
                connection.sendall(data)
    finally:
        connection.close()
        
def run_server(ip, port):
    print("Starting server {}:{}".format(repr(ip), repr(port)))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (ip, int(port))
    sock.bind(server_address)
    sock.listen(1)
    
    while True:
        connection, client_address = sock.accept()
        handle_connection (connection, client_address)

def prepare_data():
    buf = []
    for i in range (0, pow(2, 16)):
        buf.append(i & 0xff)
    return bytearray(buf)

def run_client(ip, port):
    print("Starting client {}:{}".format(repr(ip), repr(port)))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip, port)
    sock.connect(server_address)
    
    data = prepare_data()
    n_rcvd = 0
    n_sent = len (data)
    try:
        sock.sendall(data)
        
        timeout = time.time() + 2
        while n_rcvd < n_sent and time.time() < timeout:
            tmp = sock.recv(1500)
            tmp = bytearray (tmp)
            n_read = len(tmp)
            for i in range(n_read):
                if (data[n_rcvd + i] != tmp[i]):
                    print("Difference at byte {}. Sent {} got {}"
                          .format(n_rcvd + i, data[n_rcvd + i], tmp[i]))
            n_rcvd += n_read
            
        if (n_rcvd < n_sent or n_rcvd > n_sent):
            print("Sent {} and got back {}".format(n_sent, n_rcvd))
        else:
            print("Got back what we've sent!!");
            
    finally:
        sock.close()
    
def run(mode, ip, port):
    if (mode == "server"):
        run_server (ip, port)
    elif (mode == "client"):
        run_client (ip, port)
    else:
        raise Exception("Unknown mode. Only client and server supported")

if __name__ == "__main__":
    if (len(sys.argv)) < 4:
        raise Exception("Usage: ./dummy_app <mode> <ip> <port> [<action> <test>]")
    if (len(sys.argv) == 6):
        action = sys.argv[4]
        test = int(sys.argv[5])

    run (sys.argv[1], sys.argv[2], int(sys.argv[3]))
