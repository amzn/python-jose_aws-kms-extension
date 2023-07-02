# python-jose_aws-kms-extension

This library is an **extension of [python-jose](https://pypi.org/project/python-jose/) library**.
It uses [monkey-patching](https://en.wikipedia.org/wiki/Monkey_patch) to extend the capabilities of *python-jose*.
It provides JWE based encrypters/decrypters and JWS based signers/verifiers for doing operations with cryptographic
keys stored in AWS KMS. This library requires `python>=3.8,<4` and `python-jose=3.3.0`.

## Installation
[//]: # (TODO: Add link to the PyPI package, once it's released.)
You can install the library from PyPI. It's available under the name `python-jose_aws-kms-extension`.
Following is an installation example using `pip3` command.

```commandline
pip3 install python-jose_aws-kms-extension
```

## Usage
In order to use this library you'll need to import its top level package,
before importing any `python-jose` modules/packages. This ensures that monkey-patching implemented in this library
works as expected. 

```python
import jose_aws_kms_extension
from jose import <something>
```

After importing this library's top level package, you can use all existing *python-jose* features,
as you'll do in absense of this library. This library adds AWS KMS support on top of those features, in a
transparent ways. I.e., you can use your AWS KMS keys for various encryption and signing operations,
using the regular *python-jose* functions.
You can use AWS KMS specified algorithm names for these operations.
This library supports all algorithms supported by AWS KMS.
List of supported algorithms can also be viewed at the `jose_aws_kms_extension.constants.Algorithms` class.

Following are the supported *python-jose* functions:
1. `jose.jwe.encrypt()`
1. `jose.jwe.decrypt()`
1. `jose.jws.sign()`
1. `jose.jws.verify()`

This library uses [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
for all it's communication with AWS KMS.
You can provide a KMS key in one of following two possible formats:
1. *Key string*: This can be a string containing a KMS key-id, key-id ARN, key-alias or key-alias ARN.
1. *Key object*: This can be an object of one of following classes.
   Using a key object allows you to customize the *boto3* KMS client.
    1. *For encrypt/decrypt*: `jose_aws_kms_extension.backends.kms.symmetric.encryption.BotoKMSSymmetricEncryptionKey`
    1. *For sign/verify*: `jose_aws_kms_extension.backends.kms.asymmetric.signing.BotoKMSAsymmetricSigningKey`

Next sections cover few examples of encryption and signing operations supported by this library.

### Encrypt/Decrypt
#### Encrypt/Decrypt with a String Key
```python
>>> import jose_aws_kms_extension
>>> from jose import jwe

>>> jwe.encrypt(plaintext='Hello, World!', key='<your KMS key string>', algorithm='SYMMETRIC_DEFAULT', encryption='A128GCM', kid='<your KMS key string>')
b'<compact serialized JWE token>'

>>> jwe.decrypt(jwe_str=b'<compact serialized JWE token>', key='<your KMS key string>').decode('utf-8')
'Hello, World!'
```

#### Encrypt/Decrypt with a Key Object
```python
>>> import jose_aws_kms_extension
>>> from jose import jwe
>>> from jose_aws_kms_extension.backends.kms.symmetric.encryption import BotoKMSSymmetricEncryptionKey
>>> import boto3
>>> from botocore.config import Config

>>> kms_client = boto3.client('kms', config=Config(<your AWS config>))

>>> kms_encryption_key = BotoKmsSymmetricEncryptionKey(key='<your KMS key string>', algorithm='SYMMETRIC_DEFAULT', kms_client=kms_client)

>>>  jwe.encrypt(plaintext='Hello, World!', key=kms_encryption_key, algorithm='SYMMETRIC_DEFAULT', encryption='A128GCM', kid='<your KMS key string>')
b'<compact serialized JWE token>'

>>> jwe.decrypt(jwe_str=b'<compact serialized JWE token>', key=kms_encryption_key).decode('utf-8')
'Hello, World!'
```

#### Encrypt with Addition Headers
[JWS](https://datatracker.ietf.org/doc/html/rfc7515) and [JWE](https://datatracker.ietf.org/doc/html/rfc7516), 
both specs have the provision of custom (i.e. user-defined) headers. *python-jose* supports passing custom headers 
in the `headers` parameter in `jose.jws.sign()` method. But the same is not supported in `jose.jwe.encrypt()` method. 
We have opened the [issue 321](https://github.com/mpdavis/python-jose/issues/321) to add this support. 
But until the issue is resolved, we have added this capability via this library. 

Following example shows how custom headers can be passed in `jose.jwe.ecrypt()` function.
```python
>>> import jose_aws_kms_extension
>>> from jose import jwe

>>> jwe.encrypt(plaintext='Hello, World!', key='<your KMS key string>', algorithm='SYMMETRIC_DEFAULT', encryption='A128GCM', kid='<your KMS key string>', additional_headers={'addition-header1': 'val1', 'additional-header2': 'val2'})
b'<compact serialized JWE token>'
```

### Sign/Verify
#### Sign/Verify with a String Key
```python
>>> import jose_aws_kms_extension
>>> from jose import jws

>>> jws.sign(payload='Goodbye, World!'.encode('utf-8'), key='<your KMS key string>', headers={'kid': '<your KMS key string>', <other headers>},  algorithm='RSASSA_PSS_SHA_512')
'<compact serialized JWS token>'

>>> jws.verify(token='<compact serialized JWS token>', key='<your KMS key string>',  algorithms='RSASSA_PSS_SHA_512').decode('utf-8')
'Goodbye, World!'
```

#### Sign/Verify with a Key Object
```python
>>> import jose_aws_kms_extension
>>> from jose import jws
>>> from jose_aws_kms_extension.backends.kms.asymmetric.signing import BotoKMSAsymmetricSigningKey
>>> import boto3
>>> from botocore.config import Config

>>> kms_client = boto3.client('kms', config=Config(<your AWS config>))

>>> kms_signing_key = BotoKMSAsymmetricSigningKey(key='<your KMS key string>', algorithm='RSASSA_PSS_SHA_512', kms_client=kms_client)

>>> jws.sign(payload='Goodbye, World!'.encode('utf-8'), key=kms_signing_key, headers={'kid': '<your KMS key string>', <other headers>},  algorithm='RSASSA_PSS_SHA_512')
'<compact serialized JWS token>'

>>> jws.verify(token='<compact serialized JWS token>', key=kms_signing_key,  algorithms='RSASSA_PSS_SHA_512').decode('utf-8')
'Goodbye, World!'
```

## Building the Project
This project uses *[pyproject.toml](https://pip.pypa.io/en/stable/reference/build-system/pyproject-toml/)*, 
*[Poetry](https://python-poetry.org/)* and *[Poe the Poet](https://poethepoet.natn.io/)* for build. 
You'll need to install Poetry in your system before you can build the project.   

[*Poetry* Installation Guide](https://python-poetry.org/docs/#installing-with-the-official-installer) 

### First Time Dependency Installation 
After installing *Poetry* you'll need to execute the following commands for the first time depdency installation.
```commandline
poetry install
```
This command will install all the dependencies defined in *pyproject.toml* file, including *Poe the Poet*. 
After running this command for the first time, you won't need to run this command again for the successive builds.
For all future builds, you can simply run the command covered in the next section.

### Build Command
Use following command to do a release build (i.e., a full build including unit-test execution).
```commandline
poetry run poe release
```
This will execute the `release` task, which is a sequence of multiple sub-tasks. To view all sub-tasks and other 
available tasks, see the `[tool.poe.tasks]` sections in `pyproject.toml` file.

You'll need *python3.8* command to be available in your CIL's *PATH*, for the release command to be successful. 
You can either use your system's Python, *[pyenv](https://github.com/pyenv/pyenv)*, 
or whichever way you prefer for installing Python.

*Note: If you are using Homebrew on MacOS for installing/upgrading Python, then you may face following issue: 
https://github.com/python-poetry/install.python-poetry.org/issues/71*

#### Building with Other Python Versions
If you want to build the project with a Python version other than 3.8, you can use following commands
```commandline
poetry env use <your-python-version>
poetry run poe env-release
```
For more details on using your Python environment for the build, 
see *Poerty's* documentation on [Managing environments](https://python-poetry.org/docs/managing-environments/).
