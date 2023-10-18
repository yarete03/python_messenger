import socket
import threading
import time

import mysql.connector

host = '0.0.0.0'
port = 8000

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
             1)  # solution for "[Error 89] Address already in use". Use before bind()
s.bind((host, port))
s.listen(20)

all_threads = []

db_host = "localhost"
db_user = "root"
db_password = "ejea1234"
db = "python_messenger"

stop_thread_returning_chat = False


def requesting_data(connection, logged_in, ip):
    global stop_thread_returning_chat
    cursor = None
    user_id = None
    connection_to_db = None
    recipient_username = None
    thread_returning_chat_alive = False

    while True:
        try:
            data = connection.recv(4096)
            if not data:
                print(f'Connection from {ip} was closed')
                break
            if not logged_in:
                connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
                cursor = connection_to_db.cursor()
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED;")
                logged_in, user_id = login_create(connection, data, connection_to_db, cursor)
            else:
                data = decode_split_data(data)
                mode = data[0]
                if mode == 'chat_array_request':
                    listing_chats(connection, cursor, user_id)
                elif mode == 'create_new_chat':
                    recipient_username = data[1]
                    create_new_chat(connection, connection_to_db, cursor, user_id, recipient_username)
                elif mode == 'selection_of_chat':
                    recipient_username = data[1]
                    if not thread_returning_chat_alive:
                        stop_thread_returning_chat = False
                        thread_returning_chat_alive = True

                        thread_returning_chat = threading.Thread(target=returning_chat,
                                                                 args=(connection, cursor, user_id, recipient_username))
                        thread_returning_chat.start()
                elif mode == "sending_new_message":
                    new_message = data[1]
                    inserting_new_messages(user_id, recipient_username, new_message)
                elif mode == "exiting_from_chat":
                    stop_thread_returning_chat = True
        except ConnectionResetError as connection_reset_error:
            print(f'Connection from {ip}: {connection_reset_error}')


def decode_split_data(data):
    data = data.decode("utf-8")
    data = data.split(",")
    return data


def login_create(connection, data, connection_to_db, cursor):
    data = decode_split_data(data)
    mode = data[0]
    username = data[1]
    password = data[2]
    if mode == "create":
        cursor.execute("select user_id from messenger_users where username = '{}';".format(username))
        if len(cursor.fetchall()) >= 1:
            message = "000001#User already exists. Change the username.".encode('utf-8')
            logged_in = False
            user_id = None
        else:
            message = creating_user(connection_to_db, cursor, username, password)
            logged_in = False
            user_id = None
    else:
        message, logged_in, user_id = login(cursor, username, password)

    connection.send(message)
    return logged_in, user_id


def creating_user(connection_to_db, cursor, username, password):
    cursor.execute(
        "insert into messenger_users(user_id, username, password) values(null,'{}',MD5('{}'));".format(username,
                                                                                                       password))
    cursor.execute("select user_id from messenger_users where username = '{}'".format(username))
    user_id = cursor.fetchall()[0][0]
    cursor.execute(
        "create table chats_{}("
        "user_1 int(32), "
        "user_2 int(32), "
        "table_name varchar(255) not null, "
        "primary key (user_1, user_2), "
        "foreign key (user_1) references messenger_users(user_id) on delete cascade, "
        "foreign key (user_2) references messenger_users(user_id) on delete cascade);".format(
            user_id))
    connection_to_db.commit()
    message = "000000#User was successfully created! Try to log into your new user.".encode('utf-8')
    return message


def login(cursor, username, password):
    cursor.execute(
        "select user_id from messenger_users where username = '{}' and password = MD5('{}');".format(username,
                                                                                                     password))
    user_id = cursor.fetchall()
    if len(user_id) >= 1:
        message = "000000#Welcome {}!".format(username).encode('utf-8')
        logged_in = True
        user_id = user_id[0][0]
    else:
        message = "000002#Username or password are incorrect or doesn't exists. Please try again.".encode('utf-8')
        logged_in = False
        user_id = None
    return message, logged_in, user_id


def listing_chats(connection, cursor, user_id):
    cursor.execute("select username from messenger_users where user_id = (select user_2 from chats_{})".format(user_id))
    chats = cursor.fetchall()
    if len(chats) < 1:
        connection.send("000003#".encode("utf-8"))
    else:
        chats_concatenated = "000000"
        for chat in chats[0]:
            chats_concatenated = chats_concatenated + "#" + chat
        chats_concatenated = chats_concatenated.encode("utf-8")
        connection.send(chats_concatenated)


def create_new_chat(connection, connection_to_db, cursor, user_id, recipient_username):
    cursor.execute("select user_id from messenger_users where username = '{}'".format(recipient_username))
    recipient_user_id = cursor.fetchall()
    if len(recipient_user_id) < 1:
        connection.send("000004#".encode('utf-8'))
    else:
        recipient_user_id = recipient_user_id[0][0]
        table_name = str(user_id) + "_" + str(recipient_user_id)
        cursor.execute("insert into chats_{} (values ('{}', '{}', '_{}'))".format(user_id, user_id,
                                                                                  recipient_user_id, table_name))
        cursor.execute("insert into chats_{} (values ('{}', '{}', '_{}'))".format(recipient_user_id, recipient_user_id,
                                                                                  user_id, table_name))
        cursor.execute("create table _{}("
                       "message_id int(64) auto_increment, "
                       "message text(1000), "
                       "transmitter_id int(32), "
                       "recipient_id int(32), "
                       "primary key (message_id), "
                       "foreign key (recipient_id) references messenger_users(user_id) on delete cascade, "
                       "foreign key (transmitter_id) references messenger_users(user_id)on delete cascade);".format(table_name))
        connection_to_db.commit()
        connection.send("000000#".encode('utf-8'))


def returning_chat(connection, cursor, user_id, recipient_username):
    old_chat = None
    global stop_thread_returning_chat
    while not stop_thread_returning_chat:
        try:
            chat_table_name = selecting_chat_table_name(cursor, user_id, recipient_username)
            cursor.execute("select username from messenger_users where user_id = '{}'".format(user_id))
            username = cursor.fetchall()[0][0]
            cursor.execute("select message, transmitter_id from {}".format(chat_table_name))
            chat = cursor.fetchall()
            if chat == old_chat:
                pass
            elif len(chat) > 0:
                old_chat = chat
                chat_concatenated = chat_into_string(chat, username, user_id, recipient_username)
                connection.send(chat_concatenated.encode('utf-8'))
            else:
                connection.send("000006#".encode('utf-8'))
            time.sleep(1)
        except mysql.connector.errors.ProgrammingError:
            break


def chat_into_string(chat, username, user_id, recipient_username):
    chat_concatenated = "000000"
    for message in chat:
        counter = 0
        for item in message:
            if counter == 1:
                if item == user_id:
                    item = username
                else:
                    item = recipient_username
            else:
                item = str(item)
            chat_concatenated = chat_concatenated + "#" + item
            counter += 1
    return chat_concatenated


def selecting_chat_table_name(cursor, user_id, recipient_username):
    cursor.execute("select user_id from messenger_users where username = '{}'".format(recipient_username))
    recipient_user_id = cursor.fetchall()[0][0]
    cursor.execute("select table_name from chats_{} where user_2 = '{}'".format(user_id, recipient_user_id))
    chat_table_name = cursor.fetchall()[0][0]
    return chat_table_name


def inserting_new_messages(user_id, recipient_username, new_message):
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor(buffered=True)
    cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED;")
    chat_table_name = selecting_chat_table_name(cursor, user_id, recipient_username)
    cursor.execute("select user_id from messenger_users where username = '{}'".format(recipient_username))
    recipient_user_id = cursor.fetchall()[0][0]
    if new_message != "":
        cursor.execute("insert into {}(values(null,'{}','{}','{}'))".format(chat_table_name, new_message,
                                                                            user_id, recipient_user_id))
        connection_to_db.commit()


def main():
    try:
        while True:
            connection, addr = s.accept()
            ip = addr[0]
            print("New connection from {}".format(ip))
            t = threading.Thread(target=requesting_data, args=(connection, False, ip))
            t.start()
            all_threads.append(t)
    except KeyboardInterrupt:
        print("Stopped by Ctrl+C")
    finally:
        if s:
            s.close()
        for t in all_threads:
            t.join()


if __name__ == "__main__":
    main()
