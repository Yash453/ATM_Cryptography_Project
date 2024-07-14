import socket
from connect.config import \
    HOST, PORT, codes, TIMEOUT
import time

import crypto.blum_goldwasser as bg
from crypto.HMAC import HMAC
from crypto.DES import DES

from models.account import Account


def generate_private_key():
    """
    Generates a random private key within the range of 2^127 to 2^128.

    Returns:
        int: The generated private key.
    """
    from random import randint
    return randint(pow(2, 127), pow(2, 128))


def remove_first_five_zeros(bits):
    """
    Remove the first five zeros from the given bits for padding in Blum-Goldwasser Decryption.

    Args:
        bits (str): The binary string from which to remove the zeros.

    Returns:
        str: The modified binary string with the first five zeros removed.
    """
    count = 0
    modified_bits = []
    for bit in bits:
        if bit == '0' and count < 5:
            count += 1
        else:
            modified_bits.append(bit)
    return ''.join(modified_bits)


class Client(Account):
    """
    Super-class on Account that handles socket communication.
    """

    def __init__(self, name):
        super().__init__(name)
        self.__socket = None
        self.__shared_key = generate_private_key()

        self.__hard_private_key = 201506620521644331296019010208165400813

    def connect_to_server(self):
        """
        Do SSH handshake and get keys from server

        Returns:
            None
        """
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((HOST, PORT))
        self.__socket.settimeout(TIMEOUT)

        # SSL/SSH handshake steps
        self.send_hello()
        self.receive_hello()

        # key-sharing step
        time.sleep(0.1)
        self.receive_key()
        self.send_key()

        # Acknowledgement for SSL/SSH handshake
        self.receive_ack()

    def send_hello(self):
        """
        Send initial handshake

        Returns:
            None
        """
        self.__socket.sendall(b"HELLO")

    def receive_hello(self):
        """
        Receive response

        Returns:
            None
        """
        data = self.__socket.recv(1024)
        print(f"Received Hello: {data.decode()}")

    def receive_ack(self):
        """
        Recieve acknowledgement

        Returns:
            None
        """
        data = self.__socket.recv(1024)
        print(f"Received ACK: {data.decode()}")

    def receive_key(self):
        """
        Receive the public key from the server to use for encryption of the
        shared key given by the client

        Returns:
            None
        """
        scheme = DES()
        enc_key = self.__socket.recv(1024)

        decoded_server_key = scheme.decrypt(enc_key, self.__hard_private_key.to_bytes(16))

        self.server_public_key = decoded_server_key

    def send_key(self):
        """
        Send the encrypted shared key to the server.

        Returns:
            None
        """
        x0 = bg.generate_random_quadratic_residue(int.from_bytes(self.server_public_key))
        encoded_private_key = bg.encrypt(bg.int_to_binary(self.__shared_key), int.from_bytes(self.server_public_key), x0)
        # sending string of encrypted bits of private key
        self.__socket.sendall(str(encoded_private_key).encode())

    def close_connection(self):
        """
        Close connection

        Returns:
            None
        """
        print("Client closing connection")
        if self.__socket:
            self.__socket.close()

    def tcp_request(self, id, type, amount=0):
        """
        Make request to server based on user input.
        First generate package, and send to server.
        Wait for response from server and eventually
        close connection if we detect error in bank response

        Args:
            id (int): session id
            type (str): type of request
            amount (int): amount to deposit/withdraw

        Returns:
            int | None: Server response
        """
        # gen 64-bit epoch timestamp
        timestamp = time.time_ns()

        # convert user input into message
        message = codes[type]

        # get MAC (calculated with key)
        # timestamp + message + id (as string and then as bytes)
        hmessage = list(timestamp.to_bytes(8)) + list(message.encode()) + list(id)
        mac = HMAC().run(self.__shared_key.to_bytes(16), hmessage)

        # get message packet and encrypt
        plain_text = self.request(timestamp, id, mac, message, amount)
        cipher_text = self.encrypt(plain_text, self.__shared_key.to_bytes(16))

        # send encrypted message out to server
        self.__socket.sendall(cipher_text)

        # Wait for server's response and decrypt
        enc_response = self.__socket.recv(1024)
        dec_response = self.decrypt(enc_response, self.__shared_key.to_bytes(16))

        response = self.unpack_validate(dec_response, self.__shared_key)
        if response is None:
            return

        return response
