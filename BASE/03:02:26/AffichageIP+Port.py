#!/usr/bin/env python3
import socket

SERVER_IP = "10.42.227.111"
SERVER_PORT = 4567

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, SERVER_PORT))
    
    # Après connexion
    src_ip, src_port = s.getsockname()   # IP/Port local (client)
    dst_ip, dst_port = s.getpeername()   # IP/Port distant (serveur)
    
    print(f"Source:      {src_ip}:{src_port}")
    print(f"Destination: {dst_ip}:{dst_port}")
    
    # Suite du protocole
    hello = s.recv(1024).decode().strip()
    print(f"[RECV] {hello}")