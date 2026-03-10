#!/usr/bin/env python3
import socket
import hashlib
import getpass

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4567

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, SERVER_PORT))
    
    # Réception challenge
    data = s.recv(1024).decode().strip()
    challenge = data.split(" ")[1]  # "CHALL <hex>"
    print(f"[RECV] Challenge: {challenge}")
    
    # Saisie credentials
    user = input("Username: ")
    pwd = getpass.getpass("Password: ")
    
    # Envoi USER
    s.sendall(f"{user}\n".encode())
    
    # Calcul et envoi PWDHASH = SHA256(CHALL + PWD)
    pwdhash = hashlib.sha256((challenge + pwd).encode()).hexdigest()
    s.sendall(f"{pwdhash}\n".encode())
    
    # Réponse
    response = s.recv(1024).decode().strip()
    print(f"[RECV] {response}")