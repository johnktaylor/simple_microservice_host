import json
from typing import Dict, Any, List
from datetime import datetime
import logging
import base64

from .messageencryption import MessageEncryption
from .messageverification import MessageVerification
from .messagedatefunctions import MessageDateFunctions
from .messageresponse import MessageResponse

class MessageProcessing:
    def __init__(self, messageencryption: MessageEncryption, messageverification: MessageVerification, messagedatefunctions: MessageDateFunctions):
        self.messageencryption = messageencryption
        self.messageverification = messageverification
        self.messagedatefunctions = messagedatefunctions

    def verify_signature(self, signaturestring, message: Dict[str, Any]) -> bool:
        """
        Verify the cryptographic signature of a message using all available public keys.

        Args:
            message (Dict[str, Any]): The message containing the signature.

        Returns:
            bool: True if the signature is valid with any public key, False otherwise.
        """
        logging.info(f"Verifying signature")
        return self.messageverification.verify_signature(signaturestring, message)

    def sign_message(self, message: Dict[str, Any]) -> str:
        """
        Sign a message using the private key.

        Args:
            message (Dict[str, Any]): The message to be signed.

        Returns:
            str: The hexadecimal representation of the signature.
        """
        logging.info(f"Signing message")
        return self.messageverification.sign_message(message)
    
    def convert_datetime(self, datetime_str_iso8601: str) -> str:
        """
        Convert ISO 8601 datetime string to MySQL-compatible format.

        Args:
            datetime_str_iso8601 (str): The datetime string in ISO 8601 format.

        Returns:
            str: The datetime string in 'YYYY-MM-DD HH:MM:SS' format.
        """
        try:
            dt = datetime.fromisoformat(datetime_str_iso8601.replace("Z", "+00:00"))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            logging.error(f"Invalid datetime format: {datetime_str_iso8601}")
            raise

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse an ISO 8601 timestamp string into a timezone-aware datetime object.

        Args:
            timestamp_str (str): The timestamp string to parse.

        Returns:
            datetime: A timezone-aware datetime object.
        """
        logging.info(f"Parsing timestamp")
        return self.messagedatefunctions.parse_timestamp(timestamp_str)
        
    def encrypt_bytes_data(self, bytesinput: bytes, algorithm: str, client_id: str, encryption_key_override: str = None) -> bytes:
        """
        Encrypts the plaintext using AES CBC mode.

        Args:
            plaintext (str): The data to encrypt.

        Returns:
            str: The base64-encoded ciphertext.
        """
        logging.info(f"Encrypting data")
        return self.messageencryption.encrypt_bytes_data(bytesinput, algorithm, client_id, encryption_key_override)

    def decrypt_bytes_data(self, bytesinput: bytes, algorithm: str, client_id: str, encryption_key_override: str = None) -> bytes:
        """
        Decrypts the base64-encoded ciphertext using AES CBC mode.


        Args:
            ciphertext_b64 (str): The base64-encoded ciphertext.

        Returns:
            str: The decrypted plaintext.
        """
        logging.info(f"Decrypting data")
        return self.messageencryption.decrypt_bytes_data(bytesinput, algorithm, client_id, encryption_key_override)




class ClientMessageProcessing(MessageProcessing):
    def __init__(self, messageencryption: MessageEncryption, messageverification: MessageVerification, messagedatefunctions: MessageDateFunctions):
        super().__init__(messageencryption, messageverification, messagedatefunctions)





class ServerMessageProcessing(MessageProcessing):
    def __init__(self, messageencryption: MessageEncryption, messageverification: MessageVerification, messagedatefunctions: MessageDateFunctions, messageresponse: MessageResponse):
        super().__init__(messageencryption, messageverification, messagedatefunctions)
        self.messageresponse = messageresponse

    def generate_response(self, original_message: Dict[str, Any], operation: str, status: str, message: str, data: Dict[str, Any] = None, error_code: str = None) -> Dict[str, Any]:
        return self.messageresponse.generate_response(original_message, operation, status, message, data, error_code)

    def handle_request_encryption_suites(self, settings: Dict[str, Any], data: Dict[str, Any], original_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle request for encryption suites.
        """
        try:
            logging.info(f"Request encryption suites")
            encryption_suites = self.get_encryption_suites(settings)

            return self.messageresponse.generate_response(
                original_message, 
                "encryption_suites_response", 
                "success", 
                "Encryption suites request completed successfully", 
                data={"encryption_suites": encryption_suites})
        except Exception as e:
            logging.error(f"Encryption suites request failed")
            return self.messageresponse.generate_response(
                original_message, 
                "encryption_suites_response", 
                "error", 
                "Encryption suites request failed",
                error_code="ENCRYPTION_SUITES_REQUEST_FAILED"
            )

    def get_key_exchange_suites(self, settings: Dict[str, Any]) -> List[str]:
        """
        Get the list of key exchange suites supported by the message encryption object.
        """
        logging.info(f"Getting key exchange suites")
        cryptography_settings = settings.get('cryptography')
        key_exchange_suites = cryptography_settings.get('key-exchange-suites')
        logging.info(f"Key exchange suites: {key_exchange_suites}")
        return key_exchange_suites

    def get_encryption_suites(self, settings: Dict[str, Any]) -> List[str]:
        """
        Get the list of encryption suites supported by the message encryption object.
        """
        logging.info(f"Getting encryption suites")
        cryptography_settings = settings.get('cryptography')
        encryption_suites = cryptography_settings.get('encryption-suites')
        logging.info(f"Encryption suites: {encryption_suites}")
        return encryption_suites

    def handle_key_exchange_request(self, data: Dict[str, Any], original_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle key exchange request.
        """
        try:

            logging.info(f"Key exchange request")
            public_key_and_salt = self.messageencryption.handle_key_exchange_for_server(data, original_message)
            logging.info(f"Key exchange response")
            response = self.messageresponse.generate_response(
                original_message, 
                "key_exchange_response", 
                "success", 
                "Key exchange request completed successfully", 
                data={"server_public_key": public_key_and_salt.get("server_public_key"), "salt": public_key_and_salt.get("salt")})
            return response
        except Exception as e:
            logging.error(f"Key exchange request failed")
            response = self.messageresponse.generate_response(
                original_message, 
                "key_exchange_response", 
                "error", 
                "Key exchange request failed", 
                error_code="KEY_EXCHANGE_FAILED"
            )
            return response