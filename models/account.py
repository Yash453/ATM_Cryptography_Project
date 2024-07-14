from random import randint

from crypto.DES import DES
from crypto.HMAC import HMAC


class Account:
    """
    An account class to create requests from client
    and validate bank responses. Does not utilize sockets.
    """

    def __init__(self, name):
        self.name = name
        self.__timestamp = None
        self.__session = None
        self.__scheme = DES()

    def request(self, timestamp, id, mac, message, amount):
        """
        Generate a request byte object based on user input.
        """
        # convert message to bits & pad for 64 bits
        self.__timestamp = timestamp
        self.__session = id

        bit_text = list(message.encode())

        # send random amount by default
        amount_bit = randint(0, 2**32).to_bytes(4)
        # pad amount for 32 bits
        if message != "CHECK":
            amount_bit = amount.to_bytes(4)

        plain_text = list(timestamp.to_bytes(8)) + list(id) + list(mac) + list(bit_text) + list(amount_bit)
        return plain_text

    def unpack_validate(self, message, key):
        """
        Unpack response from bank and extract new balance.
        Assumes message is decrypted.
        """
        #  server_time(8) + client_time(8) + mac(32) + balance(4)

        # validate message
        server_time = message[:8]
        client_time = message[8:16]
        mac = message[16:48]
        amount = message[48:52]
        valid = self.validate(client_time, mac, key)

        # generate servers HMAC
        hmessage = list(server_time) + list(amount) + list(self.__session)
        mac_valid = HMAC().run(key.to_bytes(16), hmessage)
        # and validate
        valid = self.validate(int.from_bytes(client_time), mac, mac_valid)

        # if timestamp check fails
        if not valid:
            return

        return int.from_bytes(amount)

    def validate(self, client_time, mac, mac_valid):
        """
        Validate response from bank. Ensure that response client timestamp
        is the same as initial timestamp. Ensure mac matches information
        from bank.
        """
        return client_time == self.__timestamp and mac == mac_valid

    def encrypt(self, plain_text, key):
        """
        Encrypt via chosen scheme
        """
        cipher_text = self.__scheme.encrypt(plain_text, key)
        return cipher_text

    def decrypt(self, cipher_text, key):
        """
        Decrypt via chosen scheme
        """
        plain_text = self.__scheme.decrypt(cipher_text, key)
        return plain_text
