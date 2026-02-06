#!/usr/bin/env python3
import socket

SERVER_IP = "10.42.227.111"
SERVER_PORT = 4567

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, SERVER_PORT))
    
    # Réception Server Hello
    hello = s.recv(1024).decode().strip()
    print(f"[RECV] {hello}")
    
    # Envoi nom client
    name = "Pierre"
    s.sendall(f"{name}\n".encode())
    print(f"[SEND] {name}")
    
    # Réception réponse serveur
    response = s.recv(1024).decode().strip()
    print(f"[RECV] {response}")