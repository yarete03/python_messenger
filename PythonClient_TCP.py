import random
import socket
import platform
import os
import multiprocessing
import rsa
from getpass import getpass
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


server_ip = '127.0.0.1'
server_port = 8000
socket = socket.socket()
socket.connect((server_ip, server_port))
login_or_create_values = ["y", "n", ""]

## There is a cross asymetric communication. We have a specific keys pair for server and a different one for clients.
## This feature will encrypt all data that travels though network with RSA keys.
## On this cross way, private server key is only on server side keeping away clients
## for decrypting all communications but being able to keep the server packets save too.

server_public_key = (b'-----BEGIN RSA PUBLIC KEY-----\n'
                     b'MIIBCgKCAQEAgzn9d1bbruVsTsFT4fJ6a3eOvhHtOAEciF8XO9mS/MlXBo8Qafy/\n'
                     b'cIdisVkRyO/1Dvh29JUCIXGDIWJDDxKP5apAHB8DlyDyfOLcwa87kHR/ZfTo+k1n\n'
                     b'fY7zY0k8aDMoHIIEHAuw1gBjcWrYJ2ZM7vMTm7o+w25sXafD/QsQvdFLRs+eMoxe\n'
                     b'/21NeWrZnaQ8/7z+Y2TBChQdqIlR5IgwfJWcKt2TtKzX4r7vXEYS9TSo64P5bz1B\n'
                     b'P89A9x371QslVgWuUaIAQTv+SQ04A8XnyoQGhfIINM2orxZZJH3eryHcVW//j8cQ\n'
                     b'76Syo4rbR0lw57lCV7Fa0bpyDbSEoe4QvQIDAQAB\n'
                     b'-----END RSA PUBLIC KEY-----\n'
)

server_public_key = rsa.PublicKey.load_pkcs1(server_public_key)

salt = get_random_bytes(32)
cipher_iv = get_random_bytes(32)
password = random.choices("abcdefghijknmñopkrstuvwxyzABCDEFGHIJKNMÑOPKRSTUVWXYZ1234567890'¡.,*?¿_:;", k=20)
password = "".join([letter for letter in password])

key = PBKDF2(password, salt, dkLen=32)
cipher = AES.new(key, AES.MODE_GCM, cipher_iv)

socket.send(rsa.encrypt(key, server_public_key))
socket.recv(4096)
socket.send(rsa.encrypt(cipher_iv, server_public_key))

if platform.system() == 'Windows':
    clear_command = 'cls'
else:
    clear_command = 'clear'


def clear_console():
    os.system(clear_command)


def decode_split_decrypt_response(response):
    cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
    response = unpad(cipher.decrypt(response), AES.block_size)
    response = response.decode('utf-8')
    response = eval(response)
    return response


def encode_encrypt_send(message):
    message = str(message)
    message = message.encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
    ciphered_message = cipher.encrypt(pad(message, AES.block_size))
    socket.send(ciphered_message)


def login_create():
    login_or_create = input("Do you already have an account? [y/N]: ")
    login_or_create = login_or_create.lower()
    while login_or_create not in login_or_create_values:
        print("Invalid parameter. Please retry...")
        login_or_create = input("Do you already have an account? [y/N]: ")
        login_or_create = login_or_create.lower()
    clear_console()
    if login_or_create == "y":
        login()
    elif login_or_create == "n" or login_or_create.lower() == "":
        create_user()


def login():
    print("Log into your account")
    username = input("Username: ")
    password = getpass()
    message = ["login", username, password]
    encode_encrypt_send(message)
    response = socket.recv(4096)
    response = decode_split_decrypt_response(response)
    response_rc = response[0]
    message = response[1]
    clear_console()
    print(message)
    if response_rc == "000000":
        chat_selection()
    else:
        login_create()


def create_user():
    print("Create your user.")
    username = input("Choose your new username: ")
    password = getpass("Choose your new password: ")
    message = ["create", username, password]
    encode_encrypt_send(message)
    response = socket.recv(4096)
    response = decode_split_decrypt_response(response)
    response_rc = response[0]
    message = response[1]
    clear_console()
    print(message)
    if response_rc == "000000":
        login()
    else:
        login_create()


def chat_selection():
    while True:
        message = ["chat_array_request"]
        encode_encrypt_send(message)
        response = socket.recv(4096)
        print("Select a chat or create a new one [number/C]: ")
        response = decode_split_decrypt_response(response)
        response_rc = response[0]
        if response_rc == "000003":
            print("You do not have any chats yet. Try making a new one.")
        else:
            response.pop(0)
            count = 0
            for chat in response:
                print("{} [{}]".format(chat, count))
                count += 1
        try:
            chat_response = input()
            if chat_response.lower() == "c":
                clear_console()
                recipient_username = input("Who do you want to start a conversation with?: ")
                message = ["create_new_chat", recipient_username]
                encode_encrypt_send(message)
                response = socket.recv(4096)
                response = decode_split_decrypt_response(response)
                response_rc = response[0]
                clear_console()
                if response_rc != "000000":
                    print("There is no user named {}. Please, try again.".format(recipient_username))
                else:
                    print("New chat was successfully created!")
            else:
                try:
                    chat_response = int(chat_response)
                    username_chat_selection = response[chat_response]
                    open_chat(username_chat_selection)
                except ValueError:
                    clear_console()
                    print("You selected a wrong value. Please try again.")
        except KeyboardInterrupt:
            break


def open_chat(username_chat_selection):
    clear_console()
    message = ["selection_of_chat", username_chat_selection]
    encode_encrypt_send(message)
    starting_receiving_sending_multiprocesses()


def starting_receiving_sending_multiprocesses():
    multiprocess_reception = multiprocessing.Process(target=receiving_messages)
    multiprocess_reception.start()
    message_sender(multiprocess_reception)


def receiving_messages():
    old_chat = None
    while True:
        try:
            chat = socket.recv(4096)
            if not chat:
                break
            chat = decode_split_decrypt_response(chat)
            chat_rc = chat[0]
            if chat_rc != "000000" and old_chat is None:
                print("You have to start your new conversation")
            else:
                if old_chat != chat:
                    chat.pop(0)
                    clear_console()
                    while len(chat) > 0:
                        message = chat[0]
                        transmitter_name = chat[1]
                        print(transmitter_name + ": " + message)
                        chat = chat[2:]
            old_chat = chat.copy()
        except KeyboardInterrupt:
            break


def message_sender(multiprocess_reception):
    while True:
        try:
            new_message = None
            while new_message is None:
                new_message = input()
            new_message = ["sending_new_message", new_message]
            encode_encrypt_send(new_message)
        except KeyboardInterrupt:
            message = ["exiting_from_chat"]
            encode_encrypt_send(message)
            multiprocess_reception.terminate()
            clear_console()
            break


def main():
    try:
        clear_console()
        login_create()
        socket.close()
        clear_console()
    except KeyboardInterrupt:
        socket.close()
        clear_console()


if __name__ == "__main__":
    main()
