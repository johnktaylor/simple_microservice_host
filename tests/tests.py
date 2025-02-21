import os
import sys

# Add parent directory to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.insert(0, parent_dir)

import unittest
import logging  # Added import for logging
import uuid  # Added import for uuid
import base64
from cryptography.hazmat.primitives import padding as sym_padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from simple_microservice_host.messageserialization import MessageSerializationJson
from simple_microservice_host.messageprocessing import ClientMessageProcessing
from simple_microservice_host.messageencryption import MessageEncryption
from simple_microservice_host.messageverification import MessageVerification
from simple_microservice_host.messagedatefunctions import MessageDateFunctions
from typing import Dict, Any
import pika  # Added import for pika
import time  # Added import for time
import threading  # Added import for threading

# Configure logging to display debug messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class EncryptionTestUserRepository(unittest.TestCase):

    @classmethod
    def setUpClass(cls):    
        cls.settings = {
            "rabbitmq": {
                "host": "localhost",
                "port": 5672,
                "virtual_host": "/",
                "user": "guest",
                "password": "guest",
                "queue_name": "example_queue",
                "response_queue_name": "example_queue_response",
            },
            "cryptography": {
                "disable_signature_verification": False,
                "enforce_encryption": False,
                "encryption_suites": ["dh-aes-256-gcm", "dh-aes-256-cbc", "dh-aes-192-gcm", "dh-aes-192-cbc", "dh-aes-128-gcm", "dh-aes-128-cbc"],
                "private_key_paths": {
                    "integration_tests": "..\simple_microservice_host\examplecerts\integration_tests\donotuseinproductiontestsprivatekey.pem",
                },
                "public_key_paths": {
                    "integration_tests": "..\simple_microservice_host\examplecerts\integration_tests\donotuseinproductiontestspublickey.pem",
                },
                "public_keys_dir": "..\simple_microservice_host\examplecerts\public_keys",
            },
        }
        
        # Use the integration_tests keys directly
        private_key_path = cls.settings['cryptography']['private_key_paths']['integration_tests']
        
        cls.private_signing_key = cls.__load_private_key(private_key_path)
        
        # Check if the parameters file exists
        if os.path.exists('test_encryption_parameters.pem'):
            # If it exists, load the parameters
            with open('test_encryption_parameters.pem', 'rb') as f:
                pem_parameters = f.read()

            cls.paramaters = serialization.load_pem_parameters(pem_parameters)

        else:
            print("*****************Generating parameters*****************")
            cls.paramaters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

            pem = cls.paramaters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3  # PKCS3 is the common format for DH params
            )

            # Save parameters to a file
            with open('test_encryption_parameters.pem', 'wb') as f:
                f.write(pem)
        
        cls.server_encryption_keys = {}

        print("*****************Establishing RabbitMQ connection*****************")
        rabbitmq_config = cls.settings.get('rabbitmq', {})

        # Establish RabbitMQ connection
        cls.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=rabbitmq_config.get('host', 'localhost'),
                credentials=pika.PlainCredentials(
                    rabbitmq_config.get('user', 'guest'),
                    rabbitmq_config.get('password', 'guest')
                )
            )
        )
        cls.channel = cls.connection.channel()
        
        cls.rabbitmq_queue_name = rabbitmq_config.get('queue_name', 'user_repository')
        cls.rabbitmq_response_queue_name = rabbitmq_config.get('response_queue_name', 'user_repository_responses')

        # Declare queues
        print("*****************Declaring queues*****************")
        cls.channel.queue_declare(queue=cls.rabbitmq_queue_name)
        cls.channel.queue_declare(queue=cls.rabbitmq_response_queue_name)

        # Initialize a dictionary to hold responses keyed by request_id
        cls.responses = {}
        cls.responses_lock = threading.Lock()
        cls.response_event = threading.Event()

        # Start a thread to listen for responses
        print("*****************Starting response thread*****************")
        cls.response_thread = threading.Thread(target=cls.__listen_for_responses, daemon=True)
        cls.response_thread.start()

        cls.client_id = f"client_{str(uuid.uuid4())}"
        cls.timestamp = "2023-01-01T12:00:00Z"  # Ensure timestamp format

        cls.messageprocessing = ClientMessageProcessing(
            messageencryption = MessageEncryption(settings=cls.settings),
            messageverification = MessageVerification(
                messageserialization = MessageSerializationJson(),
                settings=cls.settings,
                component_name="integration_tests"
            ),
            messagedatefunctions = MessageDateFunctions()
        )

    @classmethod
    def tearDownClass(cls):
        # Close RabbitMQ connection
        cls.connection.close()

    @classmethod
    def __listen_for_responses(cls):
        """Listen to the 'user_repository_responses' queue and store responses based on request_id."""
        def on_response(ch, method, properties, body):
            logging.info(f"Received response before processing: {body}")
            logging.info(f"Received response before processing 2: {type(body)}")
            response = MessageSerializationJson.deserialize(body)
            logging.info(f"Received response before processing 3: {response}")
            logging.info(f"Received response before processing 4: {type(response)}")
            
            for key, value in response.items():
                logging.info(f"Key: {key}, Value: {value}")

            request_id = response.get('request_id')
            if request_id:
                with cls.responses_lock:


                    cls.responses[request_id] = response
                cls.response_event.set()
            ch.basic_ack(delivery_tag=method.delivery_tag)

        # Connect to RabbitMQ
        rabbitmq = cls.settings.get('rabbitmq')
        credentials = pika.PlainCredentials(rabbitmq['user'], rabbitmq['password'])
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq['host'], credentials=credentials))
        channel = connection.channel()
        channel.queue_declare(queue=cls.rabbitmq_response_queue_name)
        channel.basic_consume(queue=cls.rabbitmq_response_queue_name, on_message_callback=on_response)

        # Start consuming
        channel.start_consuming()

    @staticmethod
    def __load_private_key(path: str):
        with open(path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    def __perform_key_exchange_if_not_set(self, client_id, algorithm, timestamp):
        if self.__class__.server_encryption_keys.get(f"{algorithm}_{client_id}") is None:
            print("*****************Key is none, performing key exchange*****************")
            self.__class__.server_encryption_keys[f"{algorithm}_{client_id}"] = self.__perform_key_exchange(client_id, algorithm, timestamp)
        else:
            print(f"*****************Key has already been received for {algorithm}_{client_id}, returning key*****************")
        return self.__class__.server_encryption_keys[f"{algorithm}_{client_id}"]

    def __perform_key_exchange(self, client_id, algorithm, timestamp):
        print("*****************Performing key exchange*****************")

        ## Generate a private key using the parameters created in setUpClass
        client_private_key = self.__class__.paramaters.generate_private_key()

        client_public_key = client_private_key.public_key()

        message = {
            "client_id": client_id,
            "timestamp": timestamp,
            "algorithm": algorithm,
            "operation": "key_exchange_request",
            "data": {"client_public_key": client_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')},
            "comment": "key_exchange_request"
        }

        message["request_id"] = str(uuid.uuid4())
        message["signature"] = self.messageprocessing.sign_message(message)
        response = self.__send_and_receive_message(message)

        if response["status"] != "success":
            self.fail(f"Key exchange request failed with status: {response['status']}")
        
        server_public_key = response["data"]["server_public_key"].encode('utf-8')

        salt = base64.b64decode(response["data"]["salt"])

        server_public_key = serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend()
        )
        # Generate a shared secret
        shared_secret = client_private_key.exchange(server_public_key)

        if "-256-" in algorithm:
            required_bytes = 32
        elif "-192-" in algorithm:
            required_bytes = 24
        elif "-128-" in algorithm:
            required_bytes = 16
        else:
            raise ValueError(f"Invalid algorithm: {algorithm}")

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=required_bytes,
            salt=salt,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

        return derived_key
    
    def __send_and_receive_message(self, message: Dict[str, Any]):
        """Send a message and wait for the corresponding response."""
        request_id = message['request_id']  # Retrieve request_id from the message
        print("*****************Sending message*****************")
        print(message)
        print("*****************End of message*****************")

        # Publish the message
        self.channel.basic_publish(
            exchange='',
            routing_key=self.rabbitmq_queue_name,
            body=MessageSerializationJson.serialize(message),
            properties=pika.BasicProperties(
                reply_to=self.rabbitmq_response_queue_name,
                correlation_id=request_id
            )
        )
        logging.info(f"Sent message with request_id: {request_id}")

        # Wait for the response
        start_time = time.time()
        while time.time() - start_time < 15:
            with self.responses_lock:
                if request_id in self.responses:
                    response = self.responses.pop(request_id)
                    print("*****************Received response*****************")
                    print(response)
                    print("*****************End of response*****************")
                    return response
            time.sleep(0.1)  # Sleep briefly to wait for the response


        self.fail(f"No response received for request_id: {request_id} within timeout period.")

    def setUp(self):
        pass

    def test_encryption_suites(self):
        request_id = str(uuid.uuid4())
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "request_server_encryption_suites",
            "comment": "test_encryption_suites",
            "data": {"encryption_suites": ["dh-aes-256-cbc", "dh-aes-256-gcm", "dh-aes-192-cbc", "dh-aes-192-gcm", "dh-aes-128-cbc", "dh-aes-128-gcm"]}
        }
        message["request_id"] = request_id
        message["signature"] = self.messageprocessing.sign_message(message)
        response = self.__send_and_receive_message(message)
        if response["status"] != "success":

            self.fail(f"Request encryption suites failed with status: {response['status']}")
        encryption_suites = response["data"]["encryption_suites"]
        logging.info(f"Encryption suites: {encryption_suites}")
        self.assertIsNotNone(encryption_suites)
        self.assertIsInstance(encryption_suites, list)
        self.assertIn("dh-aes-256-cbc", encryption_suites)
        self.assertIn("dh-aes-256-gcm", encryption_suites)
        self.assertIn("dh-aes-192-cbc", encryption_suites)
        self.assertIn("dh-aes-192-gcm", encryption_suites)
        self.assertIn("dh-aes-128-cbc", encryption_suites)
        self.assertIn("dh-aes-128-gcm", encryption_suites)

    def test_key_exchange_for_all_algorithms(self):
        """Test the key exchange process."""
        encryption_key_256_cbc = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-256-cbc", self.timestamp)
        self.assertEqual(len(encryption_key_256_cbc), 32)

        encryption_key_256_gcm = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-256-gcm", self.timestamp)
        self.assertEqual(len(encryption_key_256_gcm), 32)

        encryption_key_192_cbc = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-192-cbc", self.timestamp)
        self.assertEqual(len(encryption_key_192_cbc), 24)

        encryption_key_192_gcm = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-192-gcm", self.timestamp)
        self.assertEqual(len(encryption_key_192_gcm), 24)

        encryption_key_128_cbc = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-128-cbc", self.timestamp)
        self.assertEqual(len(encryption_key_128_cbc), 16)

        encryption_key_128_gcm = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-128-gcm", self.timestamp)
        self.assertEqual(len(encryption_key_128_gcm), 16)

        self.assertNotEqual(encryption_key_128_gcm, encryption_key_128_cbc)

        self.assertNotEqual(encryption_key_192_gcm, encryption_key_192_cbc)

        self.assertNotEqual(encryption_key_256_gcm, encryption_key_256_cbc)

    def test_extended_functions(self):
        encryption_key = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-256-cbc", self.timestamp)

        logging.debug("Running test_extended_functions")
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "hello",
            "encrypt": True,
            "algorithm": "dh-aes-256-cbc",
            "data": {
                "message": "Hello, World!"
            },
            "comment": "test_extended_functions"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["data"] = base64.b64encode(self.messageprocessing.encrypt_bytes_data(MessageSerializationJson.serialize(message["data"]), "dh-aes-256-cbc", self.client_id, encryption_key)).decode('utf-8')
        message["signature"] = self.messageprocessing.sign_message(message)
        
        response = self.__send_and_receive_message(message)
        if response["status"] != "success":
            self.fail(f"Request hello failed with status: {response['status']}")
        

        self.assertIn("data", response)
        self.assertEqual(response["encrypt"], True)
        self.assertEqual(response["algorithm"], "dh-aes-256-cbc")

        decrypted_data = MessageSerializationJson.deserialize(self.messageprocessing.decrypt_bytes_data(base64.b64decode(response["data"]), "dh-aes-256-cbc", self.client_id, encryption_key))
        self.assertIn("message", decrypted_data)
        self.assertEqual(decrypted_data["message"], "Hey there!")

    def test_signature_failure(self):
        encryption_key = self.__perform_key_exchange_if_not_set(self.client_id, "dh-aes-256-cbc", self.timestamp)

        logging.debug("Running test_extended_functions")
        request_id = str(uuid.uuid4())  # Generate unique request_id
        message = {
            "client_id": self.client_id,
            "timestamp": self.timestamp,
            "operation": "hello",
            "encrypt": True,
            "algorithm": "dh-aes-256-cbc",
            "data": {
                "message": "Hello, World!"
            },
            "comment": "test_extended_functions"
        }
        message["request_id"] = request_id  # Include request_id in the message
        message["data"] = base64.b64encode(self.messageprocessing.encrypt_bytes_data(MessageSerializationJson.serialize(message["data"]), "dh-aes-256-cbc", self.client_id, encryption_key)).decode('utf-8')
        message["signature"] = self.messageprocessing.sign_message(message)
        message["data"] = message["data"] + "tampered message"  # Modify the message to invalidate the signature
        response = self.__send_and_receive_message(message)
        
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error_code"], "INVALID_SIGNATURE")

if __name__ == '__main__':
    unittest.main()