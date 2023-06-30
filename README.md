# Jose-Python_AWS-KMS-Extension

This library package is an extension of [python-jose](https://pypi.org/project/python-jose/) library. It provides JWE based encrypters/decrypters and JWS based signers/verifiers 
for doing operations with cryptographic keys stores in AWS KMS. This library requires Python 3.8 or above.

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
