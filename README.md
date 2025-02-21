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
python -m simple_microservice_host
```
This command uses the __main__.py file as the package entry point.
Messages will be processed according to the defined operations.

## Expanding Message Processing Functions
To extend the message processing capabilities:
- Create a subclass or extend the provided ExtendedFunctions class.
- Implement the handle_message method to support new operations.
- Register and integrate your custom processing functions in the host initialization.
- Ensure your changes work with serialization, encryption, and response generation workflows.

## Example Extended Functions
The project now includes an `ExampleExtendedFunctions` subclass which implements additional operations such as a "hello" operation. When the host receives a message with `"operation": "hello"`, it responds with a success status and a friendly message.
  
For example:
- The `ExampleExtendedFunctions` overrides `handle_message` and delegates `"hello"` to its internal method.
- You may modify or extend this functionality to support even more custom operations.

## Troubleshooting
- Ensure the `__init__.py` file is present in the package directory so that relative imports work correctly.
- Run the host with the full package name (e.g., `python -m simple_microservice_host`) instead of file paths.
- Verify your settings in `settings.yml` for RabbitMQ and cryptography configurations.

## Running Tests
To run the integration and unit tests, execute:
```bash
python tests.py
```
Notes:
- The tests add the parent directory to sys.path for proper module referencing.
- Ensure RabbitMQ is running and test configurations are correct.

## Project Structure
- `/simple_microservice_host/` : Source code for microservice host.
  - `simplemicroservicehost.py`: Main host logic (includes ExampleExtendedFunctions for demo operations).
  - `messageprocessing.py`: Message parsing and operation handling.
  - `messageserialization.py`: Serialize/Deserialize JSON messages.
  - `messageencryption.py`: Encryption/Decryption operations.
  - `messageresponse.py`: Response message generation.
  - `__main__.py`: Package entry point.
  - `__init__.py`: Package initializer.
- `settings.yml`: Configuration file for runtime settings.

## License
Distributed under the MIT License. See LICENSE for more information.

## Contributing
Contributions are welcome. Please open an issue or submit a pull request for improvements.
