# Simple Microservice Host

A lightweight microservice host for handling encrypted and signed messages with extensible processing functions.

Please note this is currently under active development.

## Overview
- Implements message serialization, encryption/decryption, and digital signature verification.
- Supports multiple encryption suites (AES CBC/GCM) and facilitates key exchange.
- Extensible via custom message processing functions.

## Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure your cryptography settings in the `settings.yml` file.

## Usage
Start the host by running:
```bash
python -m simple_microservice_host.simplemicroservicehost
```
Messages will be processed according to the defined operations.

## Expanding Message Processing Functions

To extend the message processing capabilities:
- Create a subclass or extend the provided ExtendedFunctions class.
- Implement the handle_message method to support new operations.
- Register and integrate your custom processing functions in the host initialization.
- Ensure your changes work with serialization, encryption, and response generation workflows.

## Project Structure
- `/simple_microservice_host/` : Source code for microservice host.
  - `simplemicroservicehost.py`: Main host logic.
  - `messageprocessing.py`: Message parsing and operation handling.
  - `messageserialization.py`: Serialize/Deserialize JSON messages.
  - `messageencryption.py`: Encryption/Decryption operations.
  - `messageresponse.py`: Response message generation.
- `settings.yml`: Configuration file for runtime settings.

## License
Distributed under the MIT License. See LICENSE for more information.

## Contributing
Contributions are welcome. Please open an issue or submit a pull request for improvements.
