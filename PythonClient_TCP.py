import socket
import platform
import os
import threading
import time

server_ip = '192.168.231.130'
server_port = 8000
socket = socket.socket()
socket.connect((server_ip, server_port))
login_or_create_values = ["y", "n", ""]

if platform.system() == 'Windows':
    clear_command = 'cls'
else:
    clear_command = 'clear'


def clear_console():
    os.system(clear_command)


def decode_split_response(response):
    response = response.decode('utf-8')
    response = response.split("#")
    return response


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
    password = input("Password: ")
    socket.send("login,{},{}".format(username, password).encode("utf-8"))
    response = socket.recv(4096)
    response = decode_split_response(response)
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
    socket.send("create,{},{}".format(username, password).encode("utf-8"))
    response = socket.recv(4096)
    response = decode_split_response(response)
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
        socket.send("chat_array_request,".encode("utf-8"))
        response = socket.recv(4096)
        print("Select a chat or create a new one [number/C]: ")
        response = decode_split_response(response)
        response_rc = response[0]
        if response_rc == "000003":
            print("You do not have any chats yet. Try making a new one.")
        else:
            response.pop(0)
            count = 0
            for chat in response:
                print("{} [{}]".format(chat, count))
                count += 1
        chat_response = input()
        try:
            if chat_response.lower() == "c":
                clear_console()
                recipient_username = input("Who do you want to start a conversation with?: ")
                socket.send("create_new_chat,{}".format(recipient_username).encode('utf-8'))
                response = socket.recv(4096)
                response = decode_split_response(response)
                clear_console()
                if response != "000000":
                    print("There is no user named \"{}\". Please, try again.".format(recipient_username))
                else:
                    print("New chat was successfully created!")
            else:
                try:
                    chat_response = int(chat_response)
                    username_chat_selection = response[chat_response]
                    open_chat(username_chat_selection)
                except ValueError:
                    print("You selected a wrong value. Please try again.")
        except KeyboardInterrupt:
            break


def open_chat(username_chat_selection):
    clear_console()
    username_chat_selection = "selection_of_chat," + username_chat_selection
    username_chat_selection = username_chat_selection.encode('utf-8')
    socket.send(username_chat_selection)
    starting_receiving_sending_threads()


def starting_receiving_sending_threads():
    thread_reception = threading.Thread(target=receiving_messages)
    thread_sending = threading.Thread(target=message_sender)
    thread_reception.daemon = True
    thread_sending.daemon = True
    thread_reception.start()
    thread_sending.start()
    while True:
        if not thread_reception.is_alive() or not thread_sending.is_alive():
            break


def receiving_messages():
    old_chat = None
    while True:
        chat = socket.recv(4096)
        chat = decode_split_response(chat)
        chat_rc = chat[0]
        try:
            if old_chat != chat:
                old_chat = chat.copy()
                if chat_rc == "000000":
                    chat.pop(0)
                    clear_console()
                    while len(chat) > 0:
                        message = chat[0]
                        transmitter_name = chat[1]
                        print(transmitter_name + ": " + message)
                        for i in range(2):
                            chat.pop(0)
                else:
                    print("You have to start your new conversation")
        except KeyboardInterrupt:
            socket.send("exiting_from_chat,".encode('utf-8'))
            clear_console()
            break


def message_sender():
    while True:
        new_message = input()
        if new_message is None:
            new_message = ""
        new_message = "sending_new_message," + new_message
        socket.send(new_message.encode('utf-8'))


def main():
    try:
        clear_console()
        login_create()
        socket.close()
    except KeyboardInterrupt:
        clear_console()
        socket.close()


if __name__ == "__main__":
    main()
