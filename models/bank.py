from random import randint

from crypto.DES import DES
from crypto.HMAC import HMAC


class Bank:
    """
    A bank class to process requests from client
    and validate client requests. Generates responses
    to client as well. Does not utilize sockets.
    """

    def __init__(self, name):
        self.name = name
        self.__deposits = [100]
        self.__withdrawals = []
        self.__client_timestamps = []
        self.__scheme = DES()

    def validate_respond(self, message, server_time, key):
        """
        Unpack, validate, and generate response. Assumes message is decrypted.
        """
        #  ts 8 + id 4 + mac 32 + bit_text 5 + amount_bit 4

        # get components of client message for validation
        client_time = message[:8]
        id = message[8:12]
        mac = message[12:44]
        # get request
        request = message[44:49]
        # get amount
        amount = message[49:53]

        # generate clients HMAC
        hmessage = list(client_time) + list(request) + list(id)
        mac_valid = HMAC().run(key.to_bytes(16), hmessage)
        # and validate
        valid = self.validate(int.from_bytes(client_time), server_time, mac, mac_valid)

        # default response to a random value (if message unrecognized)
        balance = randint(0, 2**32).to_bytes(4)

        # if message is corrupted, give message back to client w/garbage amount
        if not valid:
            return list(client_time) + list(client_time) + list(mac) + list(balance)

        # if valid, append client timestamp to ledger of timestamps
        self.__client_timestamps.append(int.from_bytes(client_time))

        # do action based on request
        text = request.decode("utf-8")
        balance = None
        if text == "CHECK":
            balance = self.check_balance()
        elif text == "WITHD":
            balance = self.withdraw(int.from_bytes(amount))
        elif text == "DEPOS":
            balance = self.deposit(int.from_bytes(amount))

        if balance is None:
            return

        # generate mac for client
        hmessage = list(server_time.to_bytes(8)) + list(balance) + list(id)
        mac_respond = HMAC().run(key.to_bytes(16), hmessage)

        # server_time(8) + client_time(8) + mac(32) + balance(4)
        return list(server_time.to_bytes(8)) + list(client_time) + list(mac_respond) + list(balance)

    def validate(self, client_time, server_time, mac, mac_valid):
        """
        Validate request from client. Ensure that request client timestamp
        is within reasonable range. Ensure mac matches information
        from client.
        """
        return server_time - client_time < (10 * 1e+9) and mac == mac_valid and client_time not in self.__client_timestamps

    def withdraw(self, amount):
        """
        Withdraw amount from bank. Returns new balance.
        Results in eventual hang if we request more than we
        have.
        """
        if int.from_bytes(self.check_balance()) < amount:
            return
        self.__withdrawals.append(amount)
        return self.check_balance()

    def deposit(self, amount):
        """
        Deposit amount from bank. Returns new balance.
        """
        self.__deposits.append(amount)
        return self.check_balance()

    def check_balance(self):
        """
        Sum together ledger of deposits & withdrawals.
        """
        balance = sum(self.__deposits) - sum(self.__withdrawals)
        return balance.to_bytes(4)

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
