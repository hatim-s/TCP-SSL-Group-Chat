# New CA built from scratch :: -----------------------------------------------

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import datetime
import json

issuer = {
    "Name" : "Authorized Certificate Issuer", 
    "Id" : "0xABC"
}

subject = {
    "Name" : "SecureChat", 
    "Location" :"IN",
    "Website" : "securechat.org"
}

certificate = {
    "Issuer" : issuer, 
    "Subject" : subject, 
}

certificate = json.dumps(certificate).encode('utf-8')
# print (len(certificate))

# Generate a private key
RSA_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize and save the private key to a file
private_key_pem = RSA_KEY.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.NoEncryption(),
)

with open("cert_private_key.pem", "wb") as private_key_file:
    private_key_file.write(private_key_pem)

# Generate the corresponding public key
public_key = RSA_KEY.public_key()

# Serialize and save the public key to a file
public_key_pem = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open("cert_public_key.pem", "wb") as public_key_file:
    public_key_file.write(public_key_pem)


with open("cert_private_key.pem", "rb") as private_key_file:
    private_key = serialization.load_pem_private_key(
        private_key_file.read(),
        password = None,  # No password protection
    )

# Encrypt the message
encrypted_certificate = private_key.sign(
    certificate,
    padding.PKCS1v15(),
    hashes.SHA256(), 
)

# print("Encrypted message:", encrypted_certificate)
with open("signed_certificate.pem", "wb") as server_cert_file:
    server_cert_file.write(encrypted_certificate)
