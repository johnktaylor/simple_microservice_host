import pika
import os
import sys
from typing import Dict, Any
from datetime import datetime
import logging
import base64
from .messageprocessing import ServerMessageProcessing
from .messageserialization import MessageSerializationJson, MessageSerialization
from .messageresponse import MessageResponse
from .messageencryption import MessageEncryption
from .messageverification import MessageVerification
from .messagedatefunctions import MessageDateFunctions


class ExtendedFunctions:
    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings

    def handle_message(self, message: Dict[str, Any]) -> str:
        pass

class ExampleExtendedFunctions(ExtendedFunctions):
    def __init__(self, settings: Dict[str, Any], servermessageprocessing: ServerMessageProcessing):
        super().__init__(settings)
        self.servermessageprocessing = servermessageprocessing

    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        messageresponse = MessageResponse(None, None)
        operation = message.get('operation')
        data = message.get('data', {})

        if operation == 'hello':
            return self.hello_operation(data, message)
        else:
            return self.servermessageprocessing.generate_response(message, "unknown", "error", "Operation not found", error_code="OPERATION_NOT_FOUND")

    def hello_operation(self, data: Dict[str, Any], message: Dict[str, Any]) -> Dict[str, Any]:
        return self.servermessageprocessing.generate_response(message, "hello", "success", "Example operation completed successfully", data={"message": "Hey there!"})

class SimpleMicroserviceHost:
    def __init__(
            self, 
            settings: Dict[str, Any],
            servermessageprocessing: ServerMessageProcessing,
            messageserialization: MessageSerialization,
            extendedfunctions: ExtendedFunctions):
        logging.info(f"Initializing Simple Microservice Host")

        self.servermessageprocessing = servermessageprocessing
        self.messageserialization = messageserialization
        self.extendedfunctions = extendedfunctions
        self.settings = settings

    def handle_message(self, messagebytes: bytes) -> Dict[str, Any]:
        """
        Handle incoming messages with timezone-aware timestamps.

        Args:
            message_str (str): The incoming message as a JSON string.

        Returns:
            str: The response as a JSON string.
        """
        try:
            message = self.messageserialization.deserialize(messagebytes)
        except Exception as e:
            logging.error(f"Error deserializing message: {e}")
            raise e
        
        try:
            self.servermessageprocessing.parse_timestamp_iso8601_to_datetime(message.get("timestamp"))
        except ValueError:
            return self.servermessageprocessing.generate_response(
                message, 
                message.get("operation", "unknown"), 
                "error", 
                "Invalid timestamp format", 
                error_code="INVALID_TIMESTAMP_FORMAT"
            )
        
        if not self.settings.get('cryptography').get('disable_signature_verification'):
            try:
                if not self.servermessageprocessing.verify_signature(message.get('signature'), message):
                    logging.error(f"Signature verification failed")
                    return self.servermessageprocessing.generate_response(
                        message, 
                        message.get("operation", "unknown"), 
                        "error", 
                        "Invalid signature", 
                        error_code="INVALID_SIGNATURE"
                )
            except:
                logging.error(f"Signature verification failed")

                return self.servermessageprocessing.generate_response(
                    message, 
                    message.get("operation", "unknown"), 
                    "error", 
                    "Signature verification failed", 
                    error_code="SIGNATURE_VERIFICATION_FAILED"
                )

        if message.get('encrypt'):
            logging.info(f"Encrypt flag is true")
            encrypted_data = base64.b64decode(message.get('data'))
            try:
                algorithm = message.get("algorithm")
                if not algorithm:
                    logging.error(f"Algorithm not found")
                    return self.servermessageprocessing.generate_response(message, "unknown", "error", "Algorithm not found", error_code="ALGORITHM_NOT_FOUND")
                if algorithm not in self.servermessageprocessing.get_encryption_suites(self.settings):
                    logging.error(f"Algorithm not supported")
                    return self.servermessageprocessing.generate_response(message, "unknown", "error", "Algorithm not supported", error_code="ALGORITHM_NOT_SUPPORTED")
                decrypted_data = self.servermessageprocessing.decrypt_bytes_data(encrypted_data, message.get("algorithm"), message.get("client_id"))
                logging.info(f"Decrypted data")
                message['data'] = self.messageserialization.deserialize(decrypted_data)
            except Exception as e:
                logging.error(f"Decryption failed: {e}")
                return self.servermessageprocessing.generate_response(message, "unknown", "error", "Decryption failed", error_code="DECRYPTION_FAILED")
        
        cryptography_settings = self.settings.get('cryptography')

        if cryptography_settings.get('enforce_encryption')==True:
            logging.info(f"Enforce encryption is true")
            if not message.get('encrypt'):
                logging.error(f"Encrypt flag is false and enforce encryption is true")
                return self.servermessageprocessing.generate_response(message, "unknown", "error", "Encrypt flag is false and enforce encryption is true", error_code="ENCRYPT_FLAG_FALSE_AND_ENFORCE_ENCRYPTION_TRUE")

        try:
            self.servermessageprocessing.parse_timestamp_iso8601_to_datetime(message.get("timestamp"))
    
            logging.info(f"Timestamp parsed")
        except ValueError:
            logging.error(f"Invalid timestamp format")
            return {"status": "error", "message": "Invalid timestamp format"}

        try:
            operation = message.get('operation')
            logging.info(f"Operation: {operation}")
            data = message.get('data', {})

            if operation == 'request_server_encryption_suites':
                response = self.servermessageprocessing.handle_request_encryption_suites(self.settings, data, message)
                logging.info(f"Response After Request Encryption Suites: {type(response)}")
            elif operation == 'key_exchange_request':
                response = self.servermessageprocessing.handle_key_exchange_request(data, message)
                logging.info(f"Response After Key Exchange Request: {type(response)}")
            else:
                logging.info(f"Passing Operation To Extended Functions: {operation}")
                response = self.extendedfunctions.handle_message(message)
                logging.info(f"Response After Extended Functions: {type(response)}")

        except Exception as e:
            logging.error(f"Error handling message: {e}")
            response = self.servermessageprocessing.generate_response(
                {}, 
                "unknown", 
                "error", 
                str(e), 
                error_code="GENERAL_ERROR"
            )
        
        logging.info(f"Response Before Encryption: {response}")
        
        if message.get('encrypt'):
            logging.info(f"Encrypt flag is true")
            response_data = self.messageserialization.serialize(response.get('data'))
            logging.info(f"Response data: {response_data}")
            encrypted_response_data = self.servermessageprocessing.encrypt_bytes_data(response_data, message.get("algorithm"), message.get("client_id"))
            logging.info(f"Encrypted response data")
            response['encrypt'] = True
            response['algorithm'] = message.get("algorithm")
            response['data'] = base64.b64encode(encrypted_response_data).decode('utf-8')

        return response
    
def on_request(ch, method, properties, body):
    rabbitmq_response_queue_name = rabbitmq_settings.get('response_queue_name')

    # Process the message
    logging.debug(f"Received message: {body}")

    # Handle the message
    response = simplemicroservicehost.handle_message(body)

    responsedata = MessageSerializationJson.serialize(response)

    # Send response
    ch.basic_publish(
        exchange='',
        routing_key=rabbitmq_response_queue_name,
        properties=pika.BasicProperties(correlation_id=properties.correlation_id),
        body=responsedata
    )

    # Acknowledge the message
    ch.basic_ack(delivery_tag=method.delivery_tag)

def setupExampleServer():
    global settings
    global rabbitmq_settings
    global simplemicroservicehost
    
    current_path = os.path.dirname(os.path.abspath(__file__))

    settings = {
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
                "microservicehost": current_path + "/examplecerts/microservicehost/donotuseinproductionprivatekey.pem",
            },
            "public_key_paths": {
                "microservicehost": current_path + "/examplecerts/microservicehost/donotuseinproductionpublickey.pem",
            },
            "public_keys_dir": current_path + "/examplecerts/public_keys",
        },
    }

    messageserialization = MessageSerializationJson()

    messageencryption = MessageEncryption(settings)
    messageverification = MessageVerification(settings, messageserialization)
    messagedatefunction = MessageDateFunctions()
    messageresponse = MessageResponse(messageverification, messageserialization)

    servermessageprocessing = ServerMessageProcessing(
        messageencryption, 
        messageverification, 
        messagedatefunction, 
        messageresponse
    )

    extendedfunctions = ExampleExtendedFunctions(settings, servermessageprocessing)

    simplemicroservicehost = SimpleMicroserviceHost(
        settings, 
        servermessageprocessing, 
        messageserialization, 
        extendedfunctions
    )

    # RabbitMQ connection parameters
    rabbitmq_settings = settings.get('rabbitmq')
    if not rabbitmq_settings:
        print("Error: 'rabbitmq' section is missing in settings.yml")
        sys.exit(1)
    
    rabbitmq_host = rabbitmq_settings.get('host')
    rabbitmq_user = rabbitmq_settings.get('user')
    rabbitmq_password = rabbitmq_settings.get('password')
    rabbitmq_queue_name = rabbitmq_settings.get('queue_name')
    rabbitmq_response_queue_name = rabbitmq_settings.get('response_queue_name')
    rabbitmq_port = rabbitmq_settings.get('port', 5672)
    rabbitmq_virtual_host = rabbitmq_settings.get('virtual_host', '/')
    
    if not rabbitmq_host or not rabbitmq_user or not rabbitmq_password:
        print("Error: One or more RabbitMQ configuration parameters are missing in settings.yml")
        sys.exit(1)
    
    # Establish connection to RabbitMQ
    credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_password)
    connection = pika.BlockingConnection(pika.ConnectionParameters(
        host=rabbitmq_host, port=rabbitmq_port, virtual_host=rabbitmq_virtual_host, credentials=credentials))
    channel = connection.channel()
    
    # Declare queues
    channel.queue_declare(queue=rabbitmq_queue_name)
    channel.queue_declare(queue=rabbitmq_response_queue_name)
    
    # Set up consumer
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=rabbitmq_queue_name, on_message_callback=on_request)
    
    print("Waiting for messages. To exit press CTRL+C")
    channel.start_consuming()