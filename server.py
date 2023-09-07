import threading
import socket

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.fernet import Fernet

import json

HOST = '127.0.0.1'
PORT = 59000

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER.bind((HOST, PORT))
SERVER.listen()

CLIENTS = []

RSA_KEY = PRIVATE_KEY = PUBLIC_KEY = None

# print (PRIVATE_KEY)
# print (PUBLIC_KEY)

CERTIFICATE = None

EXIT_FLAG = threading.Event()
LOCK = threading.Lock()

def send_message(message, sender, recv_clients):
    message = (sender + ": ").encode('utf-8') + message
    for client in recv_clients:
        with LOCK:
            if client in CLIENTS:
                encrypted_message = client["key"].encrypt(message)
                client["socket"].send(encrypted_message)

# Function to handle clients'connections

def disconnect_client (client):
    with LOCK:
        CLIENTS.remove(client)
    
    client["socket"].send(
        client["key"].encrypt(b'You are disconnected! We are sad to see you leave...')
    )
    client["socket"].close()
    
    send_message(f'{client["alias"]} has left the chat room!'.encode('utf-8'), "SERVER", CLIENTS)

def handle_client(client):
    while not EXIT_FLAG.is_set():
        try:
            encrypted_message = client["socket"].recv(1024)
            # print ("encrypted_message type: ", type(encrypted_message))

            recv_packet = client["key"].decrypt(encrypted_message)

            recv_packet = json.loads(recv_packet)

            message = recv_packet["message"]
            # print ("message type: ", type(message))

            receivers = recv_packet["recievers"]

            if message == "\exit":
                # client disconnected
                disconnect_client(client)
                # EXIT_FLAG.set()
                exit()

            if receivers == []:
                send_message(message, client["alias"], CLIENTS)
                continue

            # recv_alias = message.split(' ')[1].strip()

            recv_clients = []
            with LOCK:
                for c in CLIENTS:
                    if c["alias"] in receivers:
                        recv_clients.append(c)

            message = message.encode('utf-8')
            # print ("message type: ", type(message))

            if (recv_clients == []):
                send_message(b"Select a valid reciever!", client["alias"], [client])
            else:
                send_message(message, client["alias"], recv_clients)
            
        except Exception as E:
            disconnect_client(client)
            print ("Error (in 'handle_client'):", E)

            # EXIT_FLAG.set()
            exit()
    
# Main function to receive the clients connection
def receive_clients():
    while not EXIT_FLAG.is_set():
        print ("Waiting for connections...")

        clientSocket, clientAddress = SERVER.accept()
        print(f'Connection is initiated with {str(clientAddress)}')
        
        # client.send('alias?'.encode('utf-8'))
        clientHello = clientSocket.recv(1024).decode('utf-8')

        clientAlias = clientHello.split(":")[1].strip()

        print(f'The alias of this client is {clientAlias}'.encode('utf-8'))

        clientSocket.send(CERTIFICATE)
        
        clientKey = clientSocket.recv(1024)

        clientKey = RSA_KEY.decrypt(
            clientKey, 
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None,
            )
        )

        clientKey = Fernet(clientKey)

        client = {
            "socket" : clientSocket, 
            "addr" : clientAddress, 
            "alias" : clientAlias, 
            "key" : clientKey
        }

        send_message(f'{clientAlias} has connected to the chat room'.encode('utf-8'), "SERVER", CLIENTS)

        with LOCK:
            CLIENTS.append(client)

        clientSocket.send(b'You are now connected!')
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

    # exit()

# def handle_server ():
#     command = input ("Enter 'exit()' to close the server: ")
#     if command.strip() == "exit()":
#         EXIT_FLAG.set()
#         exit()

# Server Sending Certificate
if __name__ == "__main__":

    RSA_KEY = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    ) 

    PRIVATE_KEY = RSA_KEY.private_bytes(
        encoding = serialization.Encoding.PEM, 
        format = serialization.PrivateFormat.PKCS8, 
        encryption_algorithm = serialization.NoEncryption()
    )

    # Storing Public Key for use by Clients
    PUBLIC_KEY = RSA_KEY.public_key().public_bytes(
        encoding = serialization.Encoding.PEM, 
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("server_public_key.pem", "wb") as server_key_file:
        server_key_file.write(PUBLIC_KEY)

    # Reading the signed certificate from CA
    try:
        with open('signed_certificate.pem', 'rb') as certificate_file:
            CERTIFICATE = certificate_file.read()

    except FileNotFoundError:
        print(f"The signed certificate file does not exist.")
        exit ()

    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        exit()

    # threading.Thread(target = handle_server).start()

    receive_clients()