from connect.client import Client
from connect.server import Server

from multiprocessing import Process
import os
import sys

from random import randint

from helpers import hack_print, send_print, error_print, \
    success_print, header


def client_run(fileno):
    # open stdin
    sys.stdin = os.fdopen(fileno)

    # generate session ID
    id = randint(0, 2**32).to_bytes(4)

    # create bank_account object
    bank_account = Client(name="Bob")

    # handshake and get shared secret from server
    bank_account.connect_to_server()
    hack_print("Starting Client...✔\n")

    # begin Banking CLI
    while True:
        print("""
        Enter 1 to check balance
        Enter 2 to withdraw
        Enter 3 to deposit
        Enter 4 to exit
        """)
        action = input()

        match action:
            case "1":
                # make TCP request to server
                response = bank_account.tcp_request(id, action)
            case "2" | "3":
                # make TCP request to server w/ amount to withdraw/deposit
                try:
                    amount = abs(int(input("Please input amount.")))
                    if amount >= 2**32:
                        raise ValueError
                    response = bank_account.tcp_request(id, action, amount)
                except ValueError:
                    error_print("Invalid input. Try again.")
                    continue
            case "4":
                # break loop and close process
                success_print("Goodbye.")
                break
            case _:
                error_print("Unspecified. Try Again.")
                continue
        # if bank response is not valid, exit
        if response is None:
            break
        print(f"New Balance: {response}")

    # exit child process & close connection
    bank_account.close_connection()
    sys.exit()


if __name__ == "__main__":
    # clear screen
    os.system('cls' if os.name == 'nt' else 'clear')

    header()

    # start up server bank in main process
    bank = Server(name="Alice")
    rc = bank.start_server()
    hack_print("Starting Server...✔\n")

    # fork and start process (or spawn if on WindowsOS)
    fn = sys.stdin.fileno()
    client = Process(target=client_run, args=[fn])
    client.start()

    # Server shares secret with Client
    success_print("Sharing secrets")
    send_print()
    bank.share()
    success_print("Sharing COMPLETE! ✔")

    # listen for and respond to client requests
    rc = bank.tcp_listen()
    # keep listening until client closes
    while rc:
        # listen for and respond to client requests
        rc = bank.tcp_listen()

    print("Client closed! Server closing connection.")
    client.join()
    bank.close_server()
    sys.exit()
