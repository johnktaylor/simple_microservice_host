from datetime import datetime
from typing import Dict, Any
import logging
from .messageverification import MessageVerification
from .messageserialization import MessageSerialization

class MessageResponse:
    def __init__(self, messageverification: MessageVerification, messageserialization: MessageSerialization):
        self.messageverification = messageverification
        self.messageserialization = messageserialization

    def generate_response(self, original_message: Dict[str, Any], operation: str, status: str, message: str, data: Dict[str, Any] = None, error_code: str = None) -> Dict[str, Any]:
        """
        Generate a response message (common logic).
        """
        logging.info(f"Generating response")

        response = {
            "client_id": original_message.get("client_id"),
            "request_id": original_message.get("request_id"),
            "original_timestamp": original_message.get("timestamp"),
            "response_timestamp": datetime.utcnow().isoformat() + "Z",
            "operation": operation,
            "status": status,
            "message": message,
        }

        if data:
            response["data"] = data

        if original_message.get("algorithm"):
            response["algorithm"] = original_message.get("algorithm")

        if original_message.get("comment"):
            response["comment"] = original_message.get("comment")

        if error_code:
            response["error_code"] = error_code

        response['signature'] = self.messageverification.sign_message(response)
        logging.info(f"Response: {response}")
        return response

