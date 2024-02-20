import mysql.connector

# You have to create the DB and the user before executing this config script.
# Do not forget to grant the necessary permissions to the user to be able to create and manage all the contents in the DB.
# Edit the following constants with your right values:

db_host = "localhost"
db_user = "python_messenger"
db_password = "----#----"
db = "python_messenger"

connection_to_db = mysql.connector.connect(host=db_host,
                                           user=db_user,
                                           password=db_password,
                                           database=db)
cursor = connection_to_db.cursor()
cursor.execute("create table messenger_users ("
               "user_id int(32) auto_increment,"
               "username varchar(32) not null,"
               "password varchar(255) not null,"
               "primary key (user_id));")

