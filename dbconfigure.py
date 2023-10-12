import mysql.connector

db_host = "localhost"
db_user = "----"
db_password = "####"
db = "python_messenger"
connection_to_db = mysql.connector.connect(host=db_host,
                                           user=db_user,
                                           password=db_password)
cursor = connection_to_db.cursor()
cursor.execute("create database {};".format(db))
connection_to_db = mysql.connector.connect(host=db_host,
                                           user=db_user,
                                           password=db_password,
                                           database=db)
cursor = connection_to_db.cursor()
cursor.execute("create table messenger_users ("
               "user_id int(32) auto_increment,"
               "username varchar(16) not null,"
               "password varchar(255) not null,"
               "primary key (user_id));")

