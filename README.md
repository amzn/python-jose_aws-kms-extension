# Jose-Python_AWS-KMS-Extension

This library package is an extension of jwcrypto library. It provides JWE based encrypters/decrypters and JWS based signers/verifiers 
for doing operations with cryptographic keys stores in AWS KMS. This library requires Python 3.6 or above.

## Building the Project
This project uses [pyproject.toml](https://pip.pypa.io/en/stable/reference/build-system/pyproject-toml/), 
[Poetry](https://python-poetry.org/) and [Poe the Poet](https://poethepoet.natn.io/) for build. 
You'll need to install Poetry in your system before you can build the project.   

[Poetry Installation Guide](https://python-poetry.org/docs/#installing-with-the-official-installer) 

### Build Command
Use following command to do a 
release build (i.e., a full build including unit-test execution).
```commandline
poetry run poe release
```
This will execute the `release` task, which is a sequence of multiple sub-tasks. To view all sub-tasks and other 
available tasks, see the `[tool.poe.tasks]` sections in `pyproject.toml` file.
