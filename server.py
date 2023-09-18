import threading
import socket
import json

# Cryptographic Primitives for RSA (Asymmetric Key)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Cryptographic Primitives for Fernet (Symmetric Key)
from cryptography.fernet import Fernet

# Global Variables (shared across multiple threads)
SERVER = None
CLIENTS = []    # Denotes the list of clients the server is handling

RSA_KEY = None
CERTIFICATE = None

EXIT_FLAG = threading.Event()   # Flag to coordinate server exit
LOCK = threading.Lock()         # Synchronization tools

# Method to send a message from `sender` to `recv_clients`
def send_message(message, sender, recv_clients):
    message = (sender + ": ").encode('utf-8') + message
    for client in recv_clients:
        with LOCK:
            if client in CLIENTS:
                encrypted_message = client["key"].encrypt(message)
                client["socket"].send(encrypted_message)

# Function to disconnect clients: -------------------------------------------------
def disconnect_client (client):
    # Sending disconnect message
    client["socket"].send(
        client["key"].encrypt(
            b'You are disconnected! We are sad to see you leave...'
        )
    )
    client["socket"].close()

    with LOCK:
        CLIENTS.remove(client)

    # Broadcasting that client has left 
    try:
        send_message(
            f'{client["alias"]} has left the chat room!'.encode('utf-8'), 
            "SERVER", CLIENTS
        )
    
    except Exception as E:
        print (f"Error: client as already closed connection [{E}]")

# Function to handle server's connections : -------------------------------------------------
def handle_client(client):
    while not EXIT_FLAG.is_set():
        try:
            encrypted_message = client["socket"].recv(1024)
            # print ("encrypted_message type: ", type(encrypted_message))

            recv_packet = client["key"].decrypt(encrypted_message)
            recv_packet = json.loads(recv_packet)

            # Extracting the message and recievers-list
            message = recv_packet["message"]
            receivers = recv_packet["recievers"]

            if message == "\exit":
                disconnect_client(client)
                exit()

            message = message.encode('utf-8')

            # Broadcasting the message
            if receivers == None:
                send_message(message, client["alias"], CLIENTS)
                continue

            # Building the recieving client's list
            recv_clients = []
            with LOCK:
                for c in CLIENTS:
                    if c["alias"] in receivers:
                        recv_clients.append(c)

            if (recv_clients == []):
                send_message(b"Select a valid reciever!", client["alias"], [client])
            else:
                send_message(message, client["alias"], recv_clients)
            
        except Exception as E:
            disconnect_client(client)

            e_line = E.__traceback__.tb_lineno
            print (f"Error while processing client: {E} [Line: {e_line}]")

            exit()
    
# Main function to receive the clients connection
def receive_clients():
    while not EXIT_FLAG.is_set():
        print ("Waiting for connections...")

        clientSocket, clientAddress = SERVER.accept()
        print(f'Connection is initiated with {str(clientAddress)}')
        
        # 1. Extracting the client alias (SSL Handshake Begins)
        clientHello = clientSocket.recv(1024).decode('utf-8')
        clientAlias = clientHello.split(":")[1].strip()

        print(f'The alias of this client is {clientAlias}'.encode('utf-8'))

        # 2. Sending the Server Certificate
        clientSocket.send(CERTIFICATE)
        
        # 3. Recieving the client session key (symmetric)
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

        # 4. Sending the done-message (SSL Handshake Successful)
        clientSocket.send(b'You are now connected!')

        # Building the client data and appending to client list
        client = {
            "socket" : clientSocket, 
            "addr" : clientAddress, 
            "alias" : clientAlias, 
            "key" : clientKey
        }

        send_message(f'{clientAlias} has connected to the chat room'.encode('utf-8'), "SERVER", CLIENTS)

        with LOCK:
            CLIENTS.append(client)

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()


# Server Sending Certificate
if __name__ == "__main__":
    #  Socket Configurations
    HOST = '192.168.1.12'
    PORT = 59000

    #  Server Setup
    SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER.bind((HOST, PORT))
    SERVER.listen()

    # Server Assymetric Key Generation
    RSA_KEY = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    ) 

    # PRIVATE_KEY = RSA_KEY.private_bytes(
    #     encoding = serialization.Encoding.PEM, 
    #     format = serialization.PrivateFormat.PKCS8, 
    #     encryption_algorithm = serialization.NoEncryption()
    # )

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