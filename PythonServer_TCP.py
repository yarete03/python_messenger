import asyncio
import rsa
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

executor = ThreadPoolExecutor()

db_host = "localhost"
db_user = "python_messenger"
db_password = "----#----"
db = "python_messenger"

cursor_read_everything = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED;"

with open("./private.key", "rb") as key_file:
    server_private_key = rsa.PrivateKey.load_pkcs1(key_file.read())


async def handle_client(reader, writer):
    ip = writer.get_extra_info('peername')[0]
    print(f"[+] New connection from {ip}")

    key = await reader.read(4096)
    cipher_iv = await reader.read(4096)

    try:
        # RSA decryption in a thread pool
        key = await asyncio.get_event_loop().run_in_executor(executor, rsa.decrypt, key, server_private_key)
        cipher_iv = await asyncio.get_event_loop().run_in_executor(executor, rsa.decrypt, cipher_iv, server_private_key)


        # Use the decrypted AES key/IV for further communication
        await requesting_data(reader, writer, False, ip, key, cipher_iv)
    except rsa.pkcs1.DecryptionError:
        print(f"CRITICAL ALERT: Decryption failed on '{ip}' communications.")
        writer.close()


async def requesting_data(reader, writer, logged_in, ip, key, cipher_iv):
    user_id = None
    recipient_username = None
    connection_to_db = None
    returning_chat_task = None  # Task for real-time message updates

    while True:
        try:
            data = await reader.read(4096)
            if not data:
                print(f'[+] Connection from {ip} was closed')
                writer.close()
                break
            if not logged_in:
                connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password,
                                                           database=db)
                cursor = connection_to_db.cursor()
                cursor.execute(cursor_read_everything)
                logged_in, user_id = await login_create(writer, data, connection_to_db, cursor, key, cipher_iv)
            else:
                data = decode_split_decrypt_response(data, key, cipher_iv)
                mode = data[0]
                if mode == 'chat_array_request':
                    await listing_chats(writer, user_id, key, cipher_iv)
                elif mode == 'create_new_chat':
                    recipient_username = data[1]
                    await create_new_chat(writer, connection_to_db, cursor, user_id, recipient_username, key, cipher_iv)
                elif mode == 'selection_of_chat':
                    recipient_username = data[1]
                    if returning_chat_task:
                        returning_chat_task.cancel()

                    # Start the real-time message updater
                    returning_chat_task = asyncio.create_task(
                        returning_chat(writer, user_id, recipient_username, key, cipher_iv))
                elif mode == 'sending_new_message':
                    new_message = data[1]
                    await inserting_new_messages(user_id, recipient_username, new_message)
                elif mode == "exiting_from_chat":
                    if returning_chat_task:
                        returning_chat_task.cancel()
                        returning_chat_task = None
        except ConnectionResetError as connection_reset_error:
            print(f'[!] Connection from {ip}: {connection_reset_error}')
            writer.close()
            await writer.wait_closed()
            break
        except KeyboardInterrupt:
            break


async def login_create(writer, data, connection_to_db, cursor, key, cipher_iv):
    data = decode_split_decrypt_response(data, key, cipher_iv)
    mode = data[0]
    username = data[1]
    password = data[2]
    if mode == "create":
        message, logged_in, user_id = await creating_user(connection_to_db, cursor, username, password)
    else:
        message, logged_in, user_id = await login(cursor, username, password)

    encode_encrypt_send(writer, message, key, cipher_iv)
    return logged_in, user_id


def decode_split_decrypt_response(data, key, cipher_iv):
    cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
    data = unpad(cipher.decrypt(data), AES.block_size)
    data = data.decode("utf-8")
    return eval(data)


def encode_encrypt_send(writer, message, key, cipher_iv):
    message = str(message).encode("utf-8")
    cipher = AES.new(key, AES.MODE_GCM, cipher_iv)
    encrypted_message = cipher.encrypt(pad(message, AES.block_size))
    writer.write(encrypted_message)


async def creating_user(connection_to_db, cursor, username, password):
    cursor.execute("SELECT user_id FROM messenger_users WHERE username = %s", (username,))
    if len(cursor.fetchall()) >= 1:
        return ["000001", "User already exists. Change the username."], False, None
    else:
        cursor.execute("INSERT INTO messenger_users(username, password) VALUES(%s, MD5(%s))", (username, password))
        connection_to_db.commit()
        cursor.execute("SELECT user_id FROM messenger_users WHERE username = %s", (username,))
        user_id = cursor.fetchone()[0]
        cursor.execute(
            f"CREATE TABLE chats_{user_id} (user_1 INT, user_2 INT, table_name VARCHAR(255), PRIMARY KEY(user_1, user_2))")
        connection_to_db.commit()
        return ["000000", "User successfully created!"], False, user_id


async def login(cursor, username, password):
    cursor.execute("SELECT user_id FROM messenger_users WHERE username = %s AND password = MD5(%s)",
                   (username, password))
    result = cursor.fetchone()
    if result:
        return ["000000", f"Welcome {username}!"], True, result[0]
    else:
        return ["000002", "Invalid username or password."], False, None


async def listing_chats(writer, user_id, key, cipher_iv):
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor()
    cursor.execute(f"SELECT username FROM messenger_users WHERE user_id IN (SELECT user_2 FROM chats_{user_id})")
    chats = cursor.fetchall()
    if len(chats) < 1:
        encode_encrypt_send(writer, ["000003"], key, cipher_iv)
    else:
        chat_list = ["000000"] + [chat[0] for chat in chats]
        encode_encrypt_send(writer, chat_list, key, cipher_iv)


async def create_new_chat(writer, connection_to_db, cursor, user_id, recipient_username, key, cipher_iv):
    cursor.execute("SELECT user_id FROM messenger_users WHERE username = %s", (recipient_username,))
    recipient_user_id = cursor.fetchone()
    if recipient_user_id is None:
        encode_encrypt_send(writer, ["000004", "Recipient not found."], key, cipher_iv)
    else:
        recipient_user_id = recipient_user_id[0]
        table_name = f"{user_id}_{recipient_user_id}"
        cursor.execute(f"INSERT INTO chats_{user_id} (user_1, user_2, table_name) VALUES (%s, %s, %s)",
                       (user_id, recipient_user_id, f"_{table_name}"))
        cursor.execute(f"INSERT INTO chats_{recipient_user_id} (user_1, user_2, table_name) VALUES (%s, %s, %s)",
                       (recipient_user_id, user_id, f"_{table_name}"))
        cursor.execute(
            f"CREATE TABLE _{table_name} (message_id INT AUTO_INCREMENT PRIMARY KEY, message TEXT, transmitter_id INT, recipient_id INT)")
        connection_to_db.commit()
        encode_encrypt_send(writer, ["000000", "Chat created successfully!"], key, cipher_iv)


async def inserting_new_messages(user_id, recipient_username, new_message):
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor()
    cursor.execute(
        f"SELECT table_name FROM chats_{user_id} WHERE user_2 = (SELECT user_id FROM messenger_users WHERE username = %s)",
        (recipient_username,))
    chat_table_name = cursor.fetchone()[0]
    if new_message:
        cursor.execute(
            f"INSERT INTO {chat_table_name} (message, transmitter_id, recipient_id) VALUES (%s, %s, (SELECT user_id FROM messenger_users WHERE username = %s))",
            (new_message, user_id, recipient_username))
        connection_to_db.commit()


def chat_into_string(chat, username, user_id, recipient_username):
    chat_concatenated = ["000000"]
    for message, transmitter_id in chat:
        sender = username if transmitter_id == user_id else recipient_username
        chat_concatenated.append(f"{sender}: {message}")
    return chat_concatenated


async def returning_chat(writer, user_id, recipient_username, key, cipher_iv):
    old_last_line = 0
    connection_to_db = mysql.connector.connect(host=db_host, user=db_user, password=db_password, database=db)
    cursor = connection_to_db.cursor()
    cursor.execute(cursor_read_everything)

    # Get the chat table name
    chat_table_name = selecting_chat_table_name(cursor, user_id, recipient_username)

    # Get the username of the current user
    cursor.execute("""SELECT username FROM messenger_users WHERE user_id = %s""", (user_id,))
    username = cursor.fetchall()[0][0]

    # Fetch initial chat messages
    cursor.execute(f"SELECT message, transmitter_id FROM {chat_table_name}")
    chat = cursor.fetchall()

    # If there are existing messages, send them to the user
    if chat:
        cursor.execute(f"SELECT message_id FROM {chat_table_name} ORDER BY message_id DESC LIMIT 1")
        old_last_line = cursor.fetchall()[0][0]
        chat_concatenated = chat_into_string(chat, username, user_id, recipient_username)
        encode_encrypt_send(writer, chat_concatenated, key, cipher_iv)
    else:
        # If no messages, send a no messages found code
        encode_encrypt_send(writer, ["000006"], key, cipher_iv)

    # Continuously check for new messages
    while True:
        try:
            cursor.execute(f"SELECT message_id FROM {chat_table_name} ORDER BY message_id DESC LIMIT 1")
            last_line = cursor.fetchall()[0][0]

            if last_line != old_last_line:
                line_difference = last_line - old_last_line
                old_last_line = last_line
                cursor.execute(f"""SELECT message, transmitter_id 
                                   FROM {chat_table_name} 
                                   ORDER BY message_id DESC LIMIT {line_difference}""")
                chat = cursor.fetchall()

                # Convert the new chat data into a string format and send it
                chat_concatenated = chat_into_string(chat, username, user_id, recipient_username)
                encode_encrypt_send(writer, chat_concatenated, key, cipher_iv)

            # Sleep for a short time to avoid busy looping
            await asyncio.sleep(0.1)
        except IndexError:
            pass  # This occurs when no messages are found
        except mysql.connector.errors.ProgrammingError:
            break  # Handles disconnection or table errors
        except KeyboardInterrupt:
            break  # Stop the loop when the server is interrupted


def selecting_chat_table_name(cursor, user_id, recipient_username):
    cursor.execute("SELECT user_id FROM messenger_users WHERE username = %s", (recipient_username,))
    recipient_user_id = cursor.fetchone()[0]
    cursor.execute(f"SELECT table_name FROM chats_{user_id} WHERE user_2 = %s", (recipient_user_id,))
    return cursor.fetchone()[0]


async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 8000)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('[!] Closing server due keyboard interruption')