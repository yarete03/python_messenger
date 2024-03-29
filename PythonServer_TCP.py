import socket
import multiprocessing
import time
import mysql.connector
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

host = '0.0.0.0'
port = 8000

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
             1)  # solution for "[Error 89] Address already in use". Use before bind()
s.bind((host, port))
s.listen(20)

all_multiprocesses = []


db_host = "localhost"
db_user = "python_messenger"
db_password = "----#----"
db = "python_messenger"

## There is a cross asymetric communication. We have a specific keys pair for server and a different one for clients.
## This feature will encrypt all data that travels though network with RSA keys.
## On this cross way, private server key is only on server side keeping away clients
## for decrypting all communications but being able to keep the server packets save too.
with open("./private.key","rb") as key_file:
    server_private_key = key_file.read()

server_private_key = rsa.PrivateKey.load_pkcs1(server_private_key)

cursor_read_everything = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"


def requesting_data(connection, logged_in, ip, key, cipher_iv):
    cursor = None
    user_id = None
    connection_to_db = None
    recipient_username = None

    while True:
        try:
            data = connection.recv(4096)
            if not data:
                print(f'[+] Connection from {ip} was closed')
                connection.close()
                break
            if not logged_in:
                connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
                cursor = connection_to_db.cursor()
                cursor.execute(cursor_read_everything)
                logged_in, user_id = login_create(connection, data, connection_to_db, cursor, ip, key, cipher_iv)
            else:
                data = decode_split_decrypt_response(data, ip, connection, key, cipher_iv)
                mode = data[0]
                if mode == 'chat_array_request':
                    listing_chats(connection, user_id, key, cipher_iv)
                elif mode == 'create_new_chat':
                    recipient_username = data[1]
                    create_new_chat(connection, connection_to_db, cursor, user_id, recipient_username, key, cipher_iv)
                elif mode == 'selection_of_chat':
                    recipient_username = data[1]
                    multiprocess_returning_chat = multiprocessing.Process(target=returning_chat, args=(
                                                                          connection, user_id, recipient_username, key, cipher_iv))
                    multiprocess_returning_chat.start()
                elif mode == "sending_new_message":
                    new_message = data[1]
                    inserting_new_messages(user_id, recipient_username, new_message)
                elif mode == "exiting_from_chat":
                    multiprocess_returning_chat.terminate()
        except ConnectionResetError as connection_reset_error:
            print(f'[!] Connection from {ip}: {connection_reset_error}')
        except KeyboardInterrupt:
            break


def decode_split_decrypt_response(data, ip, connection, key, cipher_iv):
    try:
        cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
        data = unpad(cipher.decrypt(data), AES.block_size)
        data = data.decode("utf-8")
        data = eval(data)
        return data
    except ValueError:
        print(f"[!] CRITICAL ALERT: Decryption failed on '{ip}' communications. This could mean that someone is trying "
              f"to attack the server")
        connection.close()
        print(f"[!] WARNING: Communication with client '{ip}' was closed for security purpose")
        exit(101)


def encode_encrypt_send(connection, message, key, cipher_iv):
    message = str(message)
    message = message.encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
    ciphered_message = cipher.encrypt(pad(message, AES.block_size))
    connection.send(ciphered_message)


def login_create(connection, data, connection_to_db, cursor, ip, key, cipher_iv):
    data = decode_split_decrypt_response(data, ip, connection, key, cipher_iv)
    mode = data[0]
    username = data[1]
    password = data[2]
    if mode == "create":
        cursor.execute("""select user_id from messenger_users where username = %s;""", (username,))
        if len(cursor.fetchall()) >= 1:
            message = ["000001", "User already exists. Change the username."]
            logged_in = False
            user_id = None
        else:
            message = creating_user(connection_to_db, cursor, username, password)
            logged_in = False
            user_id = None
    else:
        message, logged_in, user_id = login(cursor, username, password)

    encode_encrypt_send(connection, message, key, cipher_iv)
    return logged_in, user_id


def creating_user(connection_to_db, cursor, username, password):
    cursor.execute("""insert into messenger_users(user_id, username, password) values(null,%s,MD5(%s));""", (username,
                                                                                                       password))
    cursor = getting_user_id(cursor, username)
    user_id = cursor.fetchall()[0][0]
    cursor.execute("create table chats_{}("
        "user_1 int(32),"
        "user_2 int(32)," 
        "table_name varchar(255) not null," 
        "primary key (user_1, user_2)," 
        "foreign key (user_1) references messenger_users(user_id) on delete cascade," 
        "foreign key (user_2) references messenger_users(user_id) on delete cascade);".format(user_id))
    connection_to_db.commit()
    message = ["000000", "User was successfully created! Try to log into your new user."]
    return message


def login(cursor, username, password):
    cursor.execute("""select user_id from messenger_users where username = %s and password = MD5(%s);""", (username,
                                                                                                     password))
    user_id = cursor.fetchall()
    if len(user_id) >= 1:
        message = ["000000", "Welcome {}!".format(username)]
        logged_in = True
        user_id = user_id[0][0]
    else:
        message = ["000002", "Username or password are incorrect or doesn't exists. Please try again."]
        logged_in = False
        user_id = None
    return message, logged_in, user_id


def getting_user_id(cursor, username):
    cursor.execute("""select user_id from messenger_users where username = %s""", (username,))
    return cursor

def listing_chats(connection, user_id, key, cipher_iv):
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor()
    cursor.execute("""select username from messenger_users where user_id in (select user_2 from chats_{})""".format(user_id))
    chats = cursor.fetchall()
    if len(chats) < 1:
        error = ["000003"]
        encode_encrypt_send(connection, error, key, cipher_iv)
    else:
        chats_concatenated = ["000000"]
        for chat in chats:
            for username in chat:
                chats_concatenated.append(username)
        encode_encrypt_send(connection, chats_concatenated, key, cipher_iv)


def create_new_chat(connection, connection_to_db, cursor, user_id, recipient_username, key, cipher_iv):
    cursor = getting_user_id(cursor, recipient_username)
    recipient_user_id = cursor.fetchall()
    if len(recipient_user_id) < 1:
        error = ["000004"]
        encode_encrypt_send(connection, error, key, cipher_iv)
    else:
        recipient_user_id = recipient_user_id[0][0]
        table_name = str(user_id) + "_" + str(recipient_user_id)
        cursor.execute("""insert into chats_{} (values (%s, %s, %s))""".format(user_id), (user_id,
                                                                                  recipient_user_id, "_" + table_name))
        cursor.execute("""insert into chats_{} (values (%s, %s, %s))""".format(recipient_user_id), (recipient_user_id,
                                                                                  user_id, "_" + table_name))
        cursor.execute("create table _{}("
                       "message_id int(64) auto_increment," 
                       "message text(1000)," 
                       "transmitter_id int(32)," 
                       "recipient_id int(32)," 
                       "primary key (message_id)," 
                       "foreign key (recipient_id) references messenger_users(user_id) on delete cascade," 
                       "foreign key (transmitter_id) references messenger_users(user_id)on delete cascade);".format(table_name))
        connection_to_db.commit()
        success = ["000000"]
        encode_encrypt_send(connection, success, key, cipher_iv)


def returning_chat(connection, user_id, recipient_username, key, cipher_iv):
    old_chat = None
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor()
    cursor.execute(cursor_read_everything)
    chat_table_name = selecting_chat_table_name(cursor, user_id, recipient_username)
    cursor.execute("""select username from messenger_users where user_id = %s""", (user_id,))
    username = cursor.fetchall()[0][0]
    while True:
        try:
            cursor.execute("""select message, transmitter_id from {}""".format(chat_table_name))
            chat = cursor.fetchall()
            if chat != old_chat:
                if len(chat) > 0:
                    old_chat = chat
                    chat_concatenated = chat_into_string(chat, username, user_id, recipient_username)
                    encode_encrypt_send(connection, chat_concatenated, key, cipher_iv)
                else:
                    encode_encrypt_send(connection, ["000006"], key, cipher_iv)
            time.sleep(0.1)
        except mysql.connector.errors.ProgrammingError:
            break
        except KeyboardInterrupt:
            break


def chat_into_string(chat, username, user_id, recipient_username):
    chat_concatenated = ["000000"]
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
            chat_concatenated.append(item)
            counter += 1
    return chat_concatenated


def selecting_chat_table_name(cursor, user_id, recipient_username):
    cursor = getting_user_id(cursor, recipient_username)
    recipient_user_id = cursor.fetchall()[0][0]
    cursor.execute("""select table_name from chats_{} where user_2 = %s""".format(user_id), (recipient_user_id,))
    chat_table_name = cursor.fetchall()[0][0]
    return chat_table_name


def inserting_new_messages(user_id, recipient_username, new_message):
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor(buffered=True)
    cursor.execute(cursor_read_everything)
    chat_table_name = selecting_chat_table_name(cursor, user_id, recipient_username)
    cursor.execute("""select user_id from messenger_users where username = %s""", (recipient_username,))
    recipient_user_id = cursor.fetchall()[0][0]
    if new_message != "":
        cursor.execute("""insert into {}(values(null,%s,%s,%s))""".format(chat_table_name), (new_message,
                                                                            user_id, recipient_user_id))
        connection_to_db.commit()


def main():
    try:
        while True:
            try:
                connection, addr = s.accept()
                ip = addr[0]
                print("[+] New connection from {}".format(ip))
                key = connection.recv(4096)
                connection.send("handshake".encode("utf-8"))
                cipher_iv = connection.recv(4096)
                try:
                    key = rsa.decrypt(key, server_private_key)
                    cipher_iv = rsa.decrypt(cipher_iv, server_private_key)
                    t = multiprocessing.Process(target=requesting_data,
                                                args=(connection, False, ip, key, cipher_iv))
                    t.start()

                    all_multiprocesses.append(t)
                except rsa.pkcs1.DecryptionError:
                    print(
                        f"CRITICAL ALERT: Decryption failed on '{ip}' communications. This could mean that someone is trying "
                        f"to attack the server")
                    connection.close()
                    print(f"WARNING: Communication with client '{ip}' was closed for security purpose")
            except KeyboardInterrupt:
                print("\n[!] Server was stopped")
                exit()
    finally:
        if s:
            s.close()
        for t in all_multiprocesses:
            t.join()


if __name__ == "__main__":
    main()
