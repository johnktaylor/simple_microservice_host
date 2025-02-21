import logging
from .simplemicroservicehost import setupExampleServer

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    setupExampleServer()
