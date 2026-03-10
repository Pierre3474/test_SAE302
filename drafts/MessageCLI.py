#!/usr/bin/env python3
import socket
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <allo>")
    sys.exit(1)

message = sys.argv[1]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("10.42.227.111", 4567))
    s.recv(1024)  # Server Hello
    s.sendall(f"{message}\n".encode())
    print(s.recv(1024).decode().strip())