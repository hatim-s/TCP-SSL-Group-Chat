import threading
import socket
import json

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.fernet import Fernet

ALIAS = input('Choose an alias >>> ')

CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
CLIENT.connect(('192.168.1.12', 59000))

SESSION_KEY = FSESSION_KEY = None

EXIT_FLAG = threading.Event()

def client_receive():
    while not EXIT_FLAG.is_set():
        try:
            encrypted_message = CLIENT.recv(1024)
            # print ("encrypted_message: ", encrypted_message)

            message = b""
            if encrypted_message:
                message = FSESSION_KEY.decrypt(encrypted_message)
            
            message = message.decode('utf-8')
            print(message)

        except Exception as E:
            print(f"Some error occured while recieving from SERVER : [{E}]")
            
            EXIT_FLAG.set()
            exit()
        
    exit()


def client_send():
    while not EXIT_FLAG.is_set():
        # Input Format : "\to name1 name2 name 3 .... nameN ; message"
        message = input("") 

        send_packet = None

        exit_flag = False
        if (message.strip() == "\exit"):
            send_packet = {
                "message" : message.strip(), 
                "recievers" : None
            }
            exit_flag = True

        elif message.startswith("\\to") == False:
            try:
                message = message.split(";")[1].strip()
            except:
                print ("Enter a valid message!")
                continue
            
            send_packet = {
                "message" : message, 
                "receivers" : []
            }

        else:
            recievers = message.split(';')[0].split(" ")[1:]
            
            try:
                message = message.split(";")[1].strip()
            except:
                print ("Enter a valid message!")
                continue

            send_packet = {
                "message" : message,  
                "recievers": recievers
            }

        # Encrypting the message:
        send_packet = json.dumps(send_packet).encode("utf-8")
        encrypted_message = FSESSION_KEY.encrypt(send_packet)

        CLIENT.send(encrypted_message)

        if exit_flag:
            CLIENT.close()

            EXIT_FLAG.set()
            exit()

    exit()

if __name__ == "__main__":

    ## Establishing the SSL Connection
    # 1. Sending Client-Hello
    CLIENT.send(f"Client-Hello : {ALIAS}".encode('utf-8'))

    # 2a. Waiting for Server Certificate 
    signature = CLIENT.recv(1024)
    # print (signature)

    certificate = {
        "Issuer" : {
            "Name" : "Authorized Certificate Issuer", 
            "Id" : "0xABC"
        },  
        "Subject": {
            "Name" : "SecureChat", 
            "Location" : "IN", 
            "Website" : "securechat.org"
        }
    } 

    certificate = json.dumps(certificate).encode('utf-8')
    # print (certificate)

    # 2b. Getting the Server Public Key (from Secured Third Party)
    CERT_PUBLIC_KEY = None
    with open("cert_public_key.pem", "rb") as public_key_file:
        CERT_PUBLIC_KEY = serialization.load_pem_public_key(public_key_file.read())

    # 3. Verifying the certificate
    try:
        certificate = CERT_PUBLIC_KEY.verify(
            signature,
            certificate,
            padding.PKCS1v15(),
            hashes.SHA256(), 
        )
        print ("Certificate is valid!")
    except Exception as e:
        print (f"Certificate might have been tampered with: {e}")
        exit()

    # 4. Creating a symmetric key for client-server session
    SESSION_KEY = Fernet.generate_key()
    # print(SESSION_KEY, type(SESSION_KEY))

    FSESSION_KEY = Fernet(SESSION_KEY)

    # 5. Sending the session-key to Server
    SERVER_PUBLIC_KEY = None
    with open("server_public_key.pem", "rb") as server_public_key_file:
        SERVER_PUBLIC_KEY = serialization.load_pem_public_key(
            server_public_key_file.read()
        )

    encrypted_session_key = SERVER_PUBLIC_KEY.encrypt(
        SESSION_KEY, 
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None,
        ),
    )

    CLIENT.send(encrypted_session_key)

    doneMessage = CLIENT.recv(1024)
    print (doneMessage.decode('utf-8'))

    receive_thread = threading.Thread(target=client_receive)
    receive_thread.start()

    send_thread = threading.Thread(target=client_send)
    send_thread.start()
    