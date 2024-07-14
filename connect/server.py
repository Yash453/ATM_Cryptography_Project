import socket
from connect.config import \
    HOST, PORT, TIMEOUT
import time

import crypto.blum_goldwasser as bg
from crypto.DES import DES

from models.bank import Bank


def generate_private_key():
    """
    Generates a random private key within the range of 2^127 to 2^128.

    Returns:
        int: The generated private key.
    """
    from random import randint
    return randint(pow(2,127), pow(2,128))


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


class Server(Bank):
    """
    Super-class on Bank that handles socket communication.
    """

    def __init__(self, name):
        super().__init__(name)
        self.__public_key, self.__private_key = bg.keygen()

        self.__hard_private_key = 201506620521644331296019010208165400813

        self.__shared_key = None
        self.__socket = None
        self.__conn = None

    def start_server(self):
        """
        Set up server and begin listening for connections

        Returns:
            None
        """
        # begin listening to the following port for when client connects
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.bind((HOST, PORT))
        self.__socket.settimeout(TIMEOUT)
        self.__socket.listen(1)

    def send_key(self):
        """
        Send key upon initial handshake

        This method sends the server's public key to the client during the initial handshake.
        The public key is encoded as a string and sent over the connection.

        Returns:
            None
        """
        scheme = DES()
        # pad public key
        padded_key = self.__public_key.to_bytes(32)
        encoded_public_key = scheme.encrypt(padded_key, self.__hard_private_key.to_bytes(16))
        self.__conn.sendall(encoded_public_key)

    def receive_key(self):
        """
        Receive the shared key from the client and decode it.

        This method receives the shared key from the client over the network connection.
        The received key is then decrypted using the server's private key and the client's public key.
        The method also removes the padding added during encryption and converts the key to an integer.

        Returns:
            None
        """
        shared_key = (self.__conn.recv(1024).decode())
        decoded_client_key = bg.decrypt(shared_key, self.__private_key, self.__public_key)

        # Removing last 5 0s that are added during padding
        last_7_bits = decoded_client_key[-7:]
        modified_last_7_bits = remove_first_five_zeros(last_7_bits)
        decoded_client_key = decoded_client_key[:-7] + modified_last_7_bits

        self.__shared_key = int(''.join([decoded_client_key[i:i+8] for i in range(0, len(decoded_client_key), 8)]),2)

    def share(self):
        """
        Share private with client after handshake

        Returns:
            None
        """
        self.__conn, _ = self.__socket.accept()

        # SSL/SSH handshake steps
        self.receive_hello()
        self.send_hello()

        # key-sharing step
        time.sleep(0.1)
        self.send_key()
        self.receive_key()

        # Acknowledgement for SSL/SSH handshake
        self.send_ACK()

    def receive_hello(self):
        """
        Receive response from the server.

        Returns:
            None
        """
        data = self.__conn.recv(1024)
        print(f"Received Hello: {data.decode()}")

    def send_hello(self):
        """
        Send initial handshake

        Returns:
            None
        """
        self.__conn.sendall(b"HELLO")

    def send_ACK(self):
        """
        Send acknowledgement

        Returns:
            None
        """
        self.__conn.sendall(b"ACK")

    def close_server(self):
        """
        Close connection and server

        Returns:
            None
        """
        if self.__conn:
            self.__conn.close()
        if self.__socket:
            self.__socket.close()

    def tcp_listen(self):
        """
        Listen for request from client based on user input.
        First decrypt then validate client response. Make appropriate changes
        to bank account if all looks good.Respond to client with new bank
        balance. Eventually close server if we detect error in client request.

        Returns:
            None
        """
        # Wait for client's request
        client_request = self.__conn.recv(1024)

        # once we start receiving none, return failure
        if not client_request:
            return 0

        # decrypt client request
        plain_client_request = self.decrypt(client_request, self.__shared_key.to_bytes(16))

        # gen 64-bit epoch timestamp
        timestamp = time.time_ns()
        # validate via mac & timestamp and make response if valid
        plain_server_response = self.validate_respond(plain_client_request, timestamp, self.__shared_key)

        # if no response, return failure
        if plain_server_response is None:
            return 0

        # encrypt and send
        cipher_text = self.encrypt(plain_server_response, self.__shared_key.to_bytes(16))

        self.__conn.sendall(cipher_text)

        return 1
