import json
from typing import Dict, Any
from datetime import datetime
import logging
import base64
from .messageprocessing import ServerMessageProcessing
from .messageserialization import MessageSerialization
from .messageresponse import MessageResponse

class ExtendedFunctions:
    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings

    def handle_message(self, message: Dict[str, Any]) -> str:
        pass

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
            self.servermessageprocessing.parse_timestamp(message.get("timestamp"))
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
            self.servermessageprocessing.parse_timestamp(message.get("timestamp"))
    
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