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
try:
    socket.connect((server_ip, server_port))
except ConnectionRefusedError:
    print('[!] It seems you do not have connection with server. Exiting...')
    exit(1)

login_or_create_values = ["y", "n", ""]

server_public_key = (b'-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAnFlwvDwPFZWpKToY+v6jnn6YZEC7Vtnt8eEyMq26cYAEGm7pSE2W\nahNR0vYAedAEQLQPHljvgkTXwrThDETfhVdNYiNb49qnVuSTbB2pzHwmiIpXQ+X1\n/49UqtT2rixAmZb/Gk8eMRQVfkXKmZ+diUtcLxD/SrXlHyKzY7kbIhOEvta2YmuK\ngJxbVDxncgbQe7DGdKNfVqj1w2ROpnMqQ4kTEsjGkHTnQpchFHQhv/0cycH4jEXd\nBtUSfx5Dc+QVESlv+SwnlUxhto0+StSnVLdivr+S59woxcQKTuPntSe5mrBmR3jL\nEgGVhUwzU+CLLag5U1F1WaFPejZomAvWuQIDAQAB\n-----END RSA PUBLIC KEY-----\n')

server_public_key = rsa.PublicKey.load_pkcs1(server_public_key)

salt = get_random_bytes(32)
cipher_iv = get_random_bytes(32)
password = random.choices("abcdefghijknmñopkrstuvwxyzABCDEFGHIJKNMÑOPKRSTUVWXYZ1234567890'¡.,*?¿_:;", k=20)
password = "".join([letter for letter in password])

key = PBKDF2(password, salt, dkLen=32)
cipher = AES.new(key, AES.MODE_GCM, cipher_iv)

socket.send(rsa.encrypt(key, server_public_key))
socket.send(rsa.encrypt(cipher_iv, server_public_key))

if platform.system() == 'Windows':
    clear_command = 'cls'
else:
    clear_command = 'clear'


def clear_console():
    os.system(clear_command)


def decode_split_decrypt_response(response):
    try:
        cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
        response = unpad(cipher.decrypt(response), AES.block_size)
        response = response.decode('utf-8')
        response = eval(response)
        return response
    except ValueError:
        print('[!] It seems you lost connection with server. Exiting...')
        exit(1)


def encode_encrypt_send(message):
    try:
        message = str(message)
        message = message.encode("utf-8")
        cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
        ciphered_message = cipher.encrypt(pad(message, AES.block_size))
        socket.send(ciphered_message)
    except BrokenPipeError:
        print('[!] It seems you lost connection with server. Exiting...')
        exit(1)


def login_create():
    login_or_create = input("Do you already have an account? [y/N]: ")
    login_or_create = login_or_create.lower()
    while login_or_create not in login_or_create_values:
        print("Invalid parameter. Please retry...")
        login_or_create = input("Do you already have an account? [y/N]: ")
        login_or_create = login_or_create.lower()
    clear_console()
    try:
        if login_or_create == "y":
            login()
        elif login_or_create == "n" or not login_or_create.strip():
            create_user()
    except KeyboardInterrupt:
        clear_console()
        login_create()


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
                try:
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
                except KeyboardInterrupt:
                    clear_console()
            else:
                try:
                    chat_number = int(chat_response)
                    try:
                        username_chat_selection = response[chat_number]
                        open_chat(username_chat_selection)
                    except IndexError:
                        clear_console()
                        print(f"[!] There is no chat with number '{chat_number}'. Please try again.")
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
    first_time = True
    while True:
        try:
            chat = socket.recv(4096)
            if not chat:
                break
            chat = decode_split_decrypt_response(chat)
            chat_rc = chat[0]
            chat.pop(0)
            if chat_rc != "000000":
                print("You have to start your new conversation")
            else:
                if first_time:
                    old_chat = chat.copy()
                    first_time = False
                elif old_chat != chat:
                    chat = old_chat + chat
                    old_chat = chat.copy()
                clear_console()
                for message in chat:
                    print(message)
        except KeyboardInterrupt:
            break


def message_sender(multiprocess_reception):
    while True:
        try:
            input_prompt = "Message: "
            print(input_prompt, end='', flush=True)
            new_message = input()
            if new_message.strip():
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