#!/usr/bin/env python

import socket
import sys
import bitstring

# action can be reflect or drop 
action = "drop"

def handle_connection (connection, client_address):
    print("Received connection from {}".format(repr(client_address)))
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break;
            if (action != "drop"):
                connection.sendall(data)
    finally:
        connection.close()
        
def run_server(ip, port):
    print("Starting server {}:{}".format(repr(ip), repr(port)))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    server_address = ("6.0.1.1", 1234)
    sock.connect(server_address)
    
    data = prepare_data()
    try:
        sock.sendall(data)
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
        raise Exception("Usage: ./dummy_app <mode> <ip> <port> [<action>]")
    if (len(sys.argv) == 5):
        action = sys.argv[4]

    run (sys.argv[1], sys.argv[2], sys.argv[3])
