from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from .algorithmsregister import AlgorithmsRegister
import base64
import os
import logging

class MessageEncryption:
    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings
        self.cryptography_settings = settings.get('cryptography')
        self.encryption_suites = self.cryptography_settings.get("encryption_suites")

        logging.info(f"Encryption Suites: {self.encryption_suites}")

        # Initialize the encryption keys, which will be used to store the derived keys for each algorithm and client ID
        self.encryption_keys = {}

        # Register the encryption algorithms
        self.algorithms_register = AlgorithmsRegister()
        self.algorithms_register.register_algorithm("dh-aes-256-cbc", MessageEncryptionAesCBC, algorithm_parameters = {'bits':256})
        self.algorithms_register.register_algorithm("dh-aes-256-gcm", MessageEncryptionAesGCM, algorithm_parameters = {'bits':256})
        self.algorithms_register.register_algorithm("dh-aes-192-cbc", MessageEncryptionAesCBC, algorithm_parameters = {'bits':192})
        self.algorithms_register.register_algorithm("dh-aes-192-gcm", MessageEncryptionAesGCM, algorithm_parameters = {'bits':192})
        self.algorithms_register.register_algorithm("dh-aes-128-cbc", MessageEncryptionAesCBC, algorithm_parameters = {'bits':128})
        self.algorithms_register.register_algorithm("dh-aes-128-gcm", MessageEncryptionAesGCM, algorithm_parameters = {'bits':128})  

    def handle_key_exchange_for_server(self, data: Dict[str, Any], original_message: Dict[str, Any])-> Dict[str, Any]:
        """
        Handle key exchange.
        """
        return self.__generate_public_key_and_encryption_key_for_server(data, original_message)

    def __generate_public_key_and_encryption_key_for_server(self, data: Dict[str, Any], original_message: Dict[str, Any])-> Dict[str, Any]:
        # Load client's public key
        client_public_key = serialization.load_pem_public_key(
            data["client_public_key"].encode('utf-8'),
            backend=default_backend()
        )

        if not original_message.get("algorithm"):
            raise ValueError("Algorithm is required")
        
        logging.info(f"Key Exchange - Algorithm Desired: {original_message.get('algorithm')}")

        print(f"Valid Algorithms: {self.encryption_suites}")

        if original_message.get("algorithm") not in self.encryption_suites:
            raise ValueError("Algorithm is not supported")
        
        logging.info(f"Key Exchange - Algorithm Supported: {original_message.get('algorithm')}")
        if not original_message.get("client_id"):
            raise ValueError("Client ID is required")
        
        logging.info(f"Key Exchange - Client ID: {original_message.get('client_id')}")
        client_id = original_message.get("client_id")
        
        algorithm = original_message.get("algorithm")

        if not client_public_key:
            raise ValueError("Client public key is required")

        # Use the client's DH parameters to generate the server's key pair
        parameters = client_public_key.parameters()
        server_private_key = parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        # Compute shared secret using the client's public key and the server's private key
        shared_secret = server_private_key.exchange(client_public_key)

        logging.info(f"Key Exchange - Shared Secret Derived")

        salt = os.urandom(16)

        if "-256-" in algorithm:
            required_bytes = 32
        elif "-192-" in algorithm:
            required_bytes = 24
        elif "-128-" in algorithm:
            required_bytes = 16
        else:
            raise ValueError(f"Invalid algorithm: {algorithm}")
        
        logging.info(f"Key Exchange - Required Bytes: {required_bytes}")

        try:
            self.encryption_keys[f"{algorithm}_{client_id}"] = {"derived_key": HKDF(
                algorithm=hashes.SHA256(),
                length=required_bytes,
                salt=salt,
                info=b'handshake data',
                    backend=default_backend()
                ).derive(shared_secret), "salt": salt}
        except Exception as e:
            logging.error(f"Key Exchange - Error Deriving Encryption Key: {e}")
            raise e

        logging.info(f"Key Exchange - Encryption Key Derived")

        logging.info(f"Key Exchange - Encryption Key Generated: {algorithm}_{client_id} with length {required_bytes}")


        # Encode the server's public key and salt

        pk_bytes = server_public_key.public_bytes(
            serialization.Encoding.PEM, 
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        base64_salt = base64.b64encode(salt).decode('utf-8')

        return {"algorithm": algorithm, "server_public_key": pk_bytes.decode('utf-8'), "salt": base64_salt}

    def encrypt_bytes_data(self, bytesinput: bytes, algorithm: str, client_id: str, encryption_key_override = None) -> bytes:
        if encryption_key_override:
            key = encryption_key_override
        else:
            key = self.encryption_keys.get(f"{algorithm}_{client_id}").get("derived_key")
        
        if not client_id:
            raise ValueError("Client ID is required")
        if not key:
            raise ValueError("Encryption key not set")
        if algorithm not in self.encryption_suites:
            raise ValueError(f"Algorithm {algorithm} not supported")
        logging.info(f"Encrypting data with algorithm {algorithm}")
        
        # Get the algorithm class and initialize it with the algorithm parameters
        algorithm_parameters = self.algorithms_register.get_algorithm(algorithm).get("algorithm_parameters")
        logging.info(f"Algorithm Parameters: {algorithm_parameters}")
        algorithm_class = self.algorithms_register.get_algorithm(algorithm)["class"](algorithm_parameters = algorithm_parameters)
        if not algorithm_class:
            raise ValueError(f"Algorithm {algorithm} not supported")
        
        return algorithm_class.encrypt_bytes_data(bytesinput, key)

    def decrypt_bytes_data(self, bytesinput: bytes, algorithm: str, client_id: str, encryption_key_override = None) -> bytes:
        if encryption_key_override:
            key = encryption_key_override
        else:
            key = self.encryption_keys.get(f"{algorithm}_{client_id}").get("derived_key")

        if not client_id:
            raise ValueError("Client ID is required")
        if not key:
            raise ValueError("Encryption key not set")
        if algorithm not in self.encryption_suites:
            raise ValueError(f"Algorithm {algorithm} not supported")
        logging.info(f"Decrypting data with algorithm {algorithm}")

        # Get the algorithm class and initialize it with the algorithm parameters
        algorithm_parameters = self.algorithms_register.get_algorithm(algorithm).get("algorithm_parameters")
        logging.info(f"Algorithm Parameters: {algorithm_parameters}")
        algorithm_class = self.algorithms_register.get_algorithm(algorithm)["class"](algorithm_parameters = algorithm_parameters)
        if not algorithm_class:
            raise ValueError(f"Algorithm {algorithm} not supported")
        
        return algorithm_class.decrypt_bytes_data(bytesinput, key)

class MessageEncryptionAesCBC:
    """
    AES-CBC encryption/decryption.
    Expects a 16-byte (128-bit) key.
    """
    def __init__(self, algorithm_parameters: Dict[str, Any]):
        self.bits = algorithm_parameters.get("bits")

    def encrypt_bytes_data(self, bytesinput: bytes, encryption_key) -> bytes:
        iv = os.urandom(16)  # Initialization vector

        if self.bits == 128:
            if len(encryption_key) != 16:
                raise ValueError("Invalid key length: 128-bit key must be 16 bytes")
        elif self.bits == 192:
            if len(encryption_key) != 24:
                raise ValueError("Invalid key length: 192-bit key must be 24 bytes")
        elif self.bits == 256:
            if len(encryption_key) != 32:
                raise ValueError("Invalid key length: 256-bit key must be 32 bytes")
        else:
            raise ValueError(f"Invalid key length: {self.bits}")

        key = encryption_key

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()

        padded_data = padder.update(bytesinput) + padder.finalize()
        encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_bytes)

    def decrypt_bytes_data(self, bytesinput: bytes, encryption_key) -> bytes:
        if self.bits == 128:
            if len(encryption_key) != 16:
                raise ValueError("Invalid key length: 128-bit key must be 16 bytes")
        elif self.bits == 192:
            if len(encryption_key) != 24:
                raise ValueError("Invalid key length: 192-bit key must be 24 bytes")
        elif self.bits == 256:
            if len(encryption_key) != 32:
                raise ValueError("Invalid key length: 256-bit key must be 32 bytes")
        else:
            raise ValueError(f"Invalid key length: {self.bits}")
        
        key = encryption_key

        ciphertext = base64.b64decode(bytesinput)
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_unencrypted_bytes = decryptor.update(actual_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()

        unencrypted_bytes = unpadder.update(padded_unencrypted_bytes) + unpadder.finalize()
        return unencrypted_bytes

class MessageEncryptionAesGCM:
    """
    AES-GCM encryption/decryption.
    Expects a 16-byte (128-bit) key.
    """
    def __init__(self, algorithm_parameters: Dict[str, Any]):        
        self.bits = algorithm_parameters.get("bits")

    def encrypt_bytes_data(self, bytesinput: bytes, encryption_key) -> bytes:
        if self.bits == 128:
            if len(encryption_key) != 16:
                raise ValueError("Invalid key length: 128-bit key must be 16 bytes")
        elif self.bits == 192:
            if len(encryption_key) != 24:
                raise ValueError("Invalid key length: 192-bit key must be 24 bytes")
        elif self.bits == 256:
            if len(encryption_key) != 32:
                raise ValueError("Invalid key length: 256-bit key must be 32 bytes")
        else:
            raise ValueError(f"Invalid key length: {self.bits}")

        key = encryption_key

        nonce = os.urandom(12)

        # Instantiate AESGCM with the derived key
        aesgcm = AESGCM(key)

        # Encrypt; no additional authenticated data (AAD) is provided here (pass None)
        ciphertext = aesgcm.encrypt(nonce, bytesinput, None)

        # Prepend the nonce to the ciphertext; both are needed for decryption
        return base64.b64encode(nonce + ciphertext)

    def decrypt_bytes_data(self, bytesinput: bytes, encryption_key) -> bytes:
        if self.bits == 128:
            if len(encryption_key) != 16:
                raise ValueError("Invalid key length: 128-bit key must be 16 bytes")
        elif self.bits == 192:
            if len(encryption_key) != 24:
                raise ValueError("Invalid key length: 192-bit key must be 24 bytes")
        elif self.bits == 256:
            if len(encryption_key) != 32:
                raise ValueError("Invalid key length: 256-bit key must be 32 bytes")
        else:
            raise ValueError(f"Invalid key length: {self.bits}")
        
        key = encryption_key

        data = base64.b64decode(bytesinput)

        nonce = data[:12]
        actual_ciphertext = data[12:]

        aesgcm = AESGCM(key)

        # Decrypt; if the ciphertext was tampered with, this will raise an exception
        plaintext_bytes = aesgcm.decrypt(nonce, actual_ciphertext, None)
        return plaintext_bytes