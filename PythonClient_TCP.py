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

client_private_key = (b'-----BEGIN RSA PRIVATE KEY-----\n'
                      b'MIIEqQIBAAKCAQEA6hpvEYjX/eM21ELwsTiws7CauWiDYCGd9PTvykK8EfA4nMCq\n'
                      b'gB9gPlWxXyO1LWBWRi/OeGsFuT1JoiIz2j0wtJhJn9YGZyU/VAt3+z+mizd6E3R1\n'
                      b'XSy2BZ1LBbvOQ0RBFXXOzRjHQ3yj/34DNkJgQ/msIAsACIBpW5y37wmw7K3pkrTq\n'
                      b'REJnmeU7qSeeO2Lccx+uVby1G5WxJB9scO+/LW23b7Os133aCEXLZMvwKrBeILdi\n'
                      b'4UggYmoGy0m5BNjDNwUu1x4z2sG5/fDKB+tOnkUP06pFVDxyw1WxEfLPUPJyr8zF\n'
                      b'2ng5/V8C9BlpPx2gvhn4VIp8TG6u3gjJMDdRXQIDAQABAoIBAQDkdoOqYxgXaCTc\n'
                      b'Ja/r5F1eH54AD6UWrfgPVPKnO1V7VCqLn+NFQlmUu+Br7tcjv36y5HjlP9zIGK3B\n'
                      b'kwtzkn/z3yMK375D7y/Mf5zKECYiezOhxOe81KOW+xh6Mfxr3TJ/FQeLVQEyNXN/\n'
                      b'JaVQ0JpN/F0ksFeJ9Hb16th6Ppl1vsJf9+qq9fvIZ+vohj4iX719EQJtZCgDsv5b\n'
                      b'2/o/c26TeFp2/gd+VTFcneGhSB001nfo2o5kHXE5ht3bpe0yLUgCcRlYnF0lvZ9R\n'
                      b'sIviY5mlD9mb5CdmEs1VRipPHTAeE9hwIBsPk3vhXCsdg29yYOdJ27BSIO1OrOjV\n'
                      b'x/BwZ/xpAoGJAO2ERuESh7Q/2w5/r4VEd5D0Ko/sWhh1GD4VZWnHZgbGccDb5Vst\n'
                      b'uB5FQy4cqlXoa/Av89zuirxrMC5kF7DwKN4uTs1WB8O+Ub/z7/mP5j0TcnCGI3BA\n'
                      b'hR8qkwSz8sPRm/pZvdFu6+S51Pmn/XtIiLNiezqyM7zLsJxkR7qt7bHTFEaakAtL\n'
                      b'xWsCeQD8UifM60qq19Mob0X1ftNAISP3A1Y5uuK3lpv/zft2AK3Vqa4TLnqXdFj1\n'
                      b'd5dfNM0GUXFRBbOJVtlHhaQcgGB4MyRKyqLomHQjZxdaypHp3FkzaYpfqOAQuUw3\n'
                      b'S0p/oI39qj6BGifmOomXCXngJUnVfefrl7V6LlcCgYhmofT6xsYK9ljS8AvJO2er\n'
                      b'JEbMACaCUP7TvO0gg0AsB04aNyrpdl0L/4PjBhH4o0EY/a+TtSQP/QVJ1oiCNZSD\n'
                      b'RWFZyyX5yGCM4Hy+yxaDJ8cYpm3j0I11hTEYJCXvxcBvsp2aRSL7p+1Gn/ehcRtY\n'
                      b'4GI9X8mJeD7tpUt1eDiw0XP+ekVqDCjXAnhVvZ0ktzfSQjDQ5q8BMy2Z9yj/gTTF\n'
                      b'vUnZVOaB0H8IpEZt+pDal8q0uKaaEx9vDMQ2x2oYPDW8D7UZ5sHTpZQihE5q09zz\n'
                      b'6QpeFWQMSBW5QFVXcR/CTeKGDFFn4L/aCrb1YeqHeFnilDW5C1FM557lWzl6Bz11\n'
                      b'3VUCgYgT53D1oCGeXIdGPfSX6qaHfUWFeQT4GjwaDUoZkfGHZHuXIK0wQabAhp8i\n'
                      b'SrZM1XRe1AiBg320A3pO4Yr5wcnwesr16kNDSWobv2yq4PVAu+mSLynyaoWlaa8S\n'
                      b'nG18THoD8ktMU8e5fUUhg4azEGk6IqEjzABJxffTn40rjhwHBaspdE9dr1EW\n'
                      b'-----END RSA PRIVATE KEY-----\n')

server_public_key = (b'-----BEGIN RSA PUBLIC KEY-----\n'
              b'MIIBCgKCAQEArYXsESibTipH2ZhNH7QY7BIgEWvU4h394Me+JnFlQk/e4WSLrIn9\n'
              b'hAfV3NTv6N665sdH2cOB3axcqEYtcRbeBThoJQ5aBKxX95E1P+S7QAXxb1H4TeyO\n'
              b'o6Qgonwi8cKQNaPCvoHKx6ci04Zcnc8WVilV3Uc/FkgbPLB6sPxMhKHPSX111zXa\n'
              b'A4QgvDpEIsF1v1VsB1TiWeVzNLHWv8sjooz9JhOZfX2XvDQWE/aILPcIEIdiEw+3\n'
              b'02SKaOraLw4s3F9+LSQRH+xZ+FESy6+xU+rG5ZKQklcrBr8k1HnGKzH3dEUndNJr\n'
              b'DktaLXtyG7U2iIaZNz5LihGOW54g3JO1PwIDAQAB\n'
              b'-----END RSA PUBLIC KEY-----\n')


client_private_key = rsa.PrivateKey.load_pkcs1(client_private_key)
server_public_key = rsa.PublicKey.load_pkcs1(server_public_key)

salt = get_random_bytes(32)
password = random.choices("abcdefghijknmñopkrstuvwxyzABCDEFGHIJKNMÑOPKRSTUVWXYZ1234567890'¡.,*?¿_:;", k=20)
password = "".join([letter for letter in password])

key = PBKDF2(password, salt, dkLen=32)
cipher = AES.new(key, AES.MODE_CBC)
cipher_iv = cipher.iv

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
    cipher = AES.new(key, AES.MODE_CBC, cipher_iv)
    #response = rsa.decrypt(response, client_private_key)
    response = unpad(cipher.decrypt(response), AES.block_size)
    response = response.decode('utf-8')
    response = response.split("#")
    return response


def encode_encrypt_send(message):
    message = message.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, cipher_iv)
    ciphered_message = cipher.encrypt(pad(message, AES.block_size))
    #ciphered_message = rsa.encrypt(ciphered_message, server_public_key)
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
    message = "login#{}#{}".format(username, password)
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
    password = input("Choose your new password: ")
    message = "create#{}#{}".format(username, password)
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
        message = "chat_array_request#"
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
                message = "create_new_chat#{}".format(recipient_username)
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
    message = "selection_of_chat#" + username_chat_selection
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
                        for i in range(2):
                            chat.pop(0)
            old_chat = chat.copy()
        except KeyboardInterrupt:
            break


def message_sender(multiprocess_reception):
    while True:
        try:
            new_message = input()
            if new_message is None:
                new_message = ""
            new_message = "sending_new_message#" + new_message
            encode_encrypt_send(new_message)
        except KeyboardInterrupt:
            message = "exiting_from_chat#"
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
