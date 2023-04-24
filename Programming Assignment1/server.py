'''
Example:
    1. Finish the server, and run it in an arbitrary directory.
    ```sh
    sudo python server.py
    ```

    2. In another directory, download any file in the folder.
    ```sh
    ftp -Aa 127.0.0.1:server.py
    ```
    In this example we download the script itself.

Remember to rename it.
'''
import re
import socket
import os

# Listening on port 52305
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 52305))
s.listen(5)  # mostly 5
# user = {'1','2','anonymous'}
# passwd = {'1','2'}
# tf = log(user[1],passwd[1])
# def log(user, password):
#     if username == 'anonymous':
#         return True
#     for i in range(len(user)):
#         if user[i] == user:
#             index = i
#             if passwd[i] != password:
#                 return True
#             else:
#                 return False
#     return False

while True:
    client, addr = s.accept()
    anony_flag = False
    logged_in = False
    connected = False
    canStoreData = False
    name_included = False
    name_id = 0
    client_port = 0
    client_ip = ""
    # Send welcome message
    client.send(b"220 12116666 ready.\r\n")
    with open('user.txt', 'rb') as ff:
        data0 = ff.readline()
        name_str = str(data0, "utf-8")
        name_str = name_str.replace('\n', '').replace('\r', '')
        names = name_str.split(" ")
        passwd = ff.readline()
        pass_str = str(passwd, "utf-8").replace('\n', '').replace('\r', '')
        passwords = pass_str.split(" ")
        lev = ff.readline()
        lev_str = str(lev,"utf-8").replace('\n','').replace('\r','')
        level = lev_str.split(" ")
    while True:
        line = client.recv(1024).decode('ascii').strip()
        print(line)
        if line[:4] == "USER":
            username = line[5:]
            if username != '':
                message = b'331 username ok, send password.\r\n'  # correct
                if names.count(username):
                    name_included = True
                    name_id = names.index(username)
                if username == 'anonymous':
                    anony_flag = True
                    canStoreData = True
            else:
                message = b'450 username cannot be null.\r\n'
            # Send welcome message
            client.send(message)

        elif line[:4] == "PASS":
            password = line[5:]
            if not anony_flag:
                if password == '':
                    client.send(b'430 Invalid username or password.\r\n')
                else:
                    if name_included:
                        if password == passwords[name_id]:
                            logged_in = True
                            if level[name_id] == 'super':
                                canStoreData = True
                    # logged_in = True
                    client.send(b'230 Login successful.\r\n')
            else:
                canStoreData = True
                logged_in = True
                client.send(b'230 Login successful.\r\n')

        elif line[:4] == "PORT":
            # Parse the data coonection ip and port
            if logged_in:
                message = line[5:]
                segments = message.split(",")
                client_ip = segments[0] + "." + segments[1] + "." + segments[2] + "." + segments[3]
                client_port = int(segments[5]) + int(segments[4]) * 256
                client.send(b'200 Active data connection established.\r\n')
                connected = True
            else:
                client.send(b'530 Not logged in.\r\n')

        elif line[:4] == "EPRT":
            # Same as PORT
            if logged_in:
                message = line[5:]
                segments = message.split("|")
                print(segments)
                client_ip = segments[2]
                # if len(segments) != 5:
                #     client.send(b'502 stablished.\r\n')
                #     continue
                print(client_ip)
                client_port = segments[3]
                # print(client_port)
                client.send(b'200 Active data connection established.\r\n')
                connected = True
            else:
                client.send(b'530 Not logged in.\r\n')

        elif line[:4] == "STOR":
            if canStoreData:
                if connected:  # client to server
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    filename = line[5:]
                    valid_name = re.findall(r'[<>:""/\?*\\]', filename)
                    if not valid_name and filename != '.':
                        try:
                            data_sock.connect((client_ip, client_port))
                            with open(filename, 'wb') as f:
                                client.send(b"125 Data connection already open. Transfer starting.\r\n")
                                while True:
                                    data = data_sock.recv(1024)
                                    f.write(data)
                                    if len(data) < 1024:
                                        break
                            data_sock.close()
                            client.send(b"226 Transfer complete.\r\n")
                        except ConnectionRefusedError:
                            client.send(b'504 File not accessible.\r\n')
                    else:
                        client.send(b'550 File not found.\r\n')
                else:
                    client.send(b'426 Not connected.\r\n')
            else:
                client.send(b'405 original user cannot store data.\r\n')

        elif line[:4] == "RETR":  # get
            if connected:
                # Same as STOR
                data_retr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                filename = line[5:]
                valid_name = re.findall(r'[<>:""/\?*\\]', filename)
                if not valid_name:
                    try:
                        data_retr.connect((client_ip, client_port))
                    except:
                        client.send(b'452 Request denied for policy reasons.\r\n')
                        continue

                    try:
                        if os.path.exists(filename):
                            if os.access(filename, os.R_OK):
                                with open(filename, 'rb+') as fp:
                                    client.send(b"150 Data connection already open. Transfer starting.\r\n")
                                    while True:
                                        data = fp.read(1024)
                                        if len(data) == 0:
                                            print("client:file send over")
                                            fp.close()
                                            break
                                        data_retr.send(data)
                                data_retr.close()
                                client.send(b"226 Transfer complete.\r\n")
                            else:
                                client.send(b'452 File not accessible.\r\n')
                        else:
                            client.send(b'452 File not found.\r\n')
                    except ConnectionRefusedError:
                        client.send(b'452 Request denied for policy reasons.\r\n')
                    except FileExistsError:
                        client.send(b'452 Not found.\r\n')
                else:
                    client.send(b'452 File not found.\r\n')
            else:
                client.send(b'452 File not found.\r\n')

        elif line[:4] == "TYPE":
            # system type
            client.send(b'200 Type set to binary.\r\n')

        elif line[:4] == 'PWD':
            client.send('257 "{}"\r\n'.format(ROOT_DIR))

        elif line[:4] == 'CWD':
            path = line.split(' ')[1]
            if os.path.isdir(os.path.join(ROOT_DIR, path)):
                ROOT_DIR = os.path.join(ROOT_DIR, path)
                client.send(b'250 OK\r\n')
            else:
                client.send(b'550 Failed\r\n')

        elif line[:4] == 'LIST':
            dir_list = os.listdir(ROOT_DIR)
            file_list = []
            for item in dir_list:
                if os.path.isfile(os.path.join(ROOT_DIR, item)):
                    file_list.append(' -rw-r--r-- 1 owner group {}\r\n'.format(item))
                else:
                    file_list.append(' drwxr-xr-x 1 owner group {}\r\n'.format(item))
            client.send(b''.join(file_list))

        elif line[:4] == "SIZE":
            filename = line[5:]
            file_size = os.path.getsize(filename)  # output
            client.send(b'213 {file_size} \r\n')
            # TODO whether right or not

        elif line[:4] == "OPTS":
            client.send(b"200 OK\r\n")

        elif line[:5] == "QUIT":
            client.send(b'221 Goodbye.\r\n')
            break
        else:
            client.send(b'504 Command not implemented.\r\n')

    client.close()
