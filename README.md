# **Python Messenger**

This app was developed just for fun and with learning prupose, but you are free to clone it and to use it if you want to.
Feel free to make pull requests if you add/modify code.

## **Dependencies**
You will need the following dependencies:
- For Server:
1. git
2. mariadb (tested on 10.11.6)
3. python3 (tested with 3.10 and 3.11)

~~~ bash
sudo apt install git python3 mariadb-server -y
~~~

- For Client:
1. git
2. python3 (tested with 3.10 and 3.11)

~~~ bash
sudo apt install git python3 -y
~~~


## **Making it works**

- On server side:

It is recomended to use virtual python environments (venv):

~~~ bash
sudo apt install python3-venv -y
python3 -m venv venv 
~~~

Clone and install libraries

~~~ bash
git clone https://github.com/yarete03/python_messenger.git
cd python_messenger
./venv/bin/pip3 install -r requirements.txt
~~~

Generate key pair to encrypt/decrypt the first message between server and client.
IMPORTANT: THE PRIVATE KEY WILL BE STORED ON A FILE CALLED "private.key". DO NOT DELETE THIS FILE! IF YOU LOSE THE FILE, YOU SHOULD GENERATE AN OTHER KEY PAIR AND YOU SHOULD CHANGE IN ALL CLIENTS THE PUBLIC_KEY

~~~ bash
./venv/bin/python3 key_gen.py
~~~

Copy the public key retrieved in the terminal and change it on the PythonClient_TCP.py: 

~~~ python
server_public_key = (b'retrieved public key')
~~~

Create a database and a user to manage it. Remember to change values given as an example:

~~~ bash
mysql
create database 'database_name';
create user 'username'@'allowed_ip_range' identified by 'password';
grant all on database_name.* to 'username'@'allowed_ip_range';
~~~

You should change 'dbconfigure.py' and 'PythonServer_TCP.py' to fix your db configuration:

~~~ python
db_host = "mariadb_IP/mariadb_DNS"
db_user = "username"
db_password = "password"
db = "database_name"
~~~

Now you should execute 'dbconfigure.py' to configure the database:

~~~ bash
./venv/bin/python3 dbconfigure.py
~~~

Once it is configured, server should be ready to be launched:

~~~ bash
sudo ./venv/bin/python3 PythonServer_TCP.py
~~~

If you want to run it as an standalone:

~~~ bash
sudo ./venv/bin/python3 PythonServer_TCP.py > /var/log/python_server.log 2>&1 & disown
~~~

- On client side:

It is recomended to use virtual python environments (venv):

~~~ bash
sudo apt install python3-venv -y
python3 -m venv venv 
~~~

Clone and install libraries

~~~ bash
git clone https://github.com/yarete03/python_messenger.git
cd python_messenger
./venv/bin/pip3 install -r requirements.txt
~~~

Copy the public key retrieved in the server when executed 'key_gen.py' and change it on the PythonClient_TCP.py: 

~~~ python
server_public_key = (b'retrieved public key')
~~~

Change IP on 'PythonClient_TCP.py' in order to aim your server:


~~~ python
server_ip = 'python_server_IP/DNS'
~~~

Execute the client:

~~~ bash
./venv/bin/python3 PythonClient_TCP.py
~~~
