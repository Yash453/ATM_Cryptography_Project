# Account/Bank-Client/Server Secure Communication

This project describes the following:

1) Client/Server communication via TCP socket
2) Basic CLI interaction
3) SSH/SSL Handshake, as well as key-sharing via Blum-Goldwasser
4) Triple-DES Encryption

## Set Up

To run this project, you will need a conda environment, which can be created after installing [anaconda](https://docs.anaconda.com/free/anaconda/install/index.html). 

Conda should also be added to your path. Follow the respective guides based on your operating system:
* [Windows](https://saturncloud.io/blog/setting-up-anaconda-path-environment-variable-in-windows-a-guide/)
* [MacOS](https://saturncloud.io/blog/adding-anaconda-to-your-path-a-guide-for-data-scientists/#:~:text=On%20macOS%20and%20Linux%3A%20Open,path%20to%20your%20Anaconda%20installation.)

To run this project without a conda environment, you just need to ensure that your local environment satisfies the following:
* You are using Python 3.11
* You've installed the following packages via pip:
    * bitarray
    * colorama
    * sympy

After installing Anaconda and adding it to your path you can then create the necessary conda environment (named `crypto`) by running

```bash
conda env create --file environment.yml
```

After this environment has been created, verify that it is listed as an environment and activate it:

```bash
conda env list
conda activate crypto
```

## Usage

Once you have activated the `crypto` environment, you can run this project by executing:

```
python -m run
```

After the header displays and secrets are shared, input numbers into the terminal to interact with your bank account. You start out with `100` in your bank account for testing purposes.

```
Enter 1 to check balance
Enter 2 to withdraw
Enter 3 to deposit
Enter 4 to exit
```