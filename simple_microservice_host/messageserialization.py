import json
from typing import Dict, Any
import logging

class MessageSerialization:
    @staticmethod
    def serialize(message: Dict[str, Any]) -> bytes:
        pass

    @staticmethod
    def deserialize(message: bytes) -> Dict[str, Any]:
        pass

class MessageSerializationJson(MessageSerialization):
    @staticmethod
    def serialize(message: Dict[str, Any]) -> bytes:
        #logging.info(f"Serializing message: {message}")
        try:
            logging.info(f"Serializing message type: {type(message)}")
            logging.info(f"Message: {message}")
            serializedmessage = json.dumps(message).encode('utf-8')
            logging.info(f"Serialized message: {serializedmessage}")
            logging.info(f"Serialized message type: {type(serializedmessage)}")
            return serializedmessage
        except Exception as e:
            logging.error(f"Error serializing message: {e}")
            raise e

    @staticmethod
    def deserialize(message: bytes) -> Dict[str, Any]:
        #logging.info(f"Deserializing message: {message}")
        try:
            logging.info(f"Deserializing message type: {type(message)}")
            logging.info(f"Message: {message}")
            deserializedmessage = json.loads(message.decode('utf-8'))
            logging.info(f"Deserialized message: {deserializedmessage}")
            logging.info(f"Deserialized message type: {type(deserializedmessage)}")
            return deserializedmessage
        except Exception as e:
            logging.error(f"Error deserializing message: {e}")
            raise e

