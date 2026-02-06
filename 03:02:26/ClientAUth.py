#!/usr/bin/env python3
import socket
import getpass

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4567

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, SERVER_PORT))
    
    # Réception Server AUTH
    auth_prompt = s.recv(1024).decode().strip()
    print(f"[RECV] {auth_prompt}")
    
    # Envoi USER
    user = input("Username: ")
    s.sendall(f"{user}\n".encode())
    
    # Envoi PWD
    pwd = getpass.getpass("Password: ")
    s.sendall(f"{pwd}\n".encode())
    
    # Réponse serveur
    response = s.recv(1024).decode().strip()
    print(f"[RECV] {response}")