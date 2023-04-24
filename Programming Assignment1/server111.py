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

# Listening on port 21
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 52305))
s.listen(5)

while True:
    client, addr = s.accept()
    client.send(b"220 12110818 ready.\r\n")
    # Send welcome message
    client_ip = ""
    client_port = 0
    line = client.recv(1024).decode('ascii').strip()
    isloggin = False
    isano = False
    iscnted = False
    issuper = False
    username = ""

    while line != "QUIT":
        print(line)
        if line[:4] == "USER":
            username = line[5:]
            if username == "":
                client.send(b"450 Username cannot be null.\r\n")
            else:
                message2 = b"331 Username ok, send password.\r\n"
                client.send(message2)
                if username == "anonymous":
                    isano = True
            # Send welcome messageaa


        elif line[:4] == "PORT":
            if isloggin:
                msg = line[5:]
                ip_port = msg.split(",")
                ip = ip_port[0] + "." + ip_port[1] + "." + ip_port[2] + "." + ip_port[3]
                print(ip)
                port = int(ip_port[4]) * 256 + int(ip_port[5])
                print(port)
                client.send(b"200 Active data connection established.\r\n")
                client_ip = ip
                client_port = port
                iscnted = True
            else:
                client.send(b"530 Not logged in.\r\n")
            # Parse the data coonection ip and port

            pass

        elif line[:4] == "EPRT":
            if isloggin:
                msg = line[5:]
                ip_port = msg.split("|")
                print(ip_port)
                ip = ip_port[2]
                port = int(ip_port[3])
                client.send(b"200 Active data connection established.\r\n")
                client_ip = ip
                client_port = port
                iscnted = True
            else:
                client.send(b"530 Not logged in.\r\n")
            # Same as PORT
            pass

        elif line[:4] == "STOR":  # 上传
            print(issuper)
            if issuper:
                if iscnted:
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    illegal_characters = r'[<>:""/\?*\\]'
                    try:
                        data_sock.connect((client_ip, client_port))
                        filename = line[5:]
                        if not re.findall(illegal_characters, filename) and not filename == ".":
                            with open(filename, 'wb') as f:
                                client.send(b"125 Data connection already open. Transfer starting.\r\n")
                                while True:
                                    data = data_sock.recv(1024)
                                    f.write(data)
                                    if len(data) < 1024:
                                        break
                            data_sock.close()
                            client.send(b"226 Transfer complete.\r\n")
                        else:
                            data_sock.close()
                            client.send(b"452 Illegal filename.\r\n")
                    except ConnectionRefusedError:
                        data_sock.close()
                        client.send(b"421 Service not available, closing control connection.\r\n")
                else:
                    client.send(b"444 file transmission before connecting.\r\n")
            else:
                client.send(b"444 Not accessible for ordinary user.\r\n")
            # Establish data connection
            pass

        elif line[:4] == "RETR":  # 下载
            if isloggin:
                if iscnted:
                    print(client_ip)
                    print(client_port)
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    illegal_characters = r'[<>:""/\?*\\]'
                    try:
                        data_sock.connect((client_ip, client_port))
                        filename = line[5:].strip()
                        if not re.findall(illegal_characters, filename):
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
                                            data_sock.send(data)
                                    data_sock.close()
                                    client.send(b"226 Transfer complete.\r\n")
                                else:
                                    data_sock.close()
                                    client.send(b"452 File not accessible.\r\n")
                            else:
                                data_sock.close()
                                client.send(b"452 File not found.\r\n")
                        else:
                            data_sock.close()
                            client.send(b"452 Illegal filename.\r\n")
                    except ConnectionRefusedError:
                        data_sock.close()
                        client.send(b"421 Service not available, closing control connection.\r\n")
                else:
                    client.send(b"444 file transmission before connecting.\r\n")
            else:
                client.send(b"530 Not logged in.\r\n")
            # Same as STOR
            pass

        elif line[:4] == "SIZE":
            filename = line[5:]
            fsize = os.path.getsize(filename)
            client.send(b"220 " + str(fsize).encode('ascii'))

            pass

        elif line[:4] == "PASS":
            password = line[5:]
            isfound = False
            message = b""
            if isano:
                isloggin = True
                message = b"230 login successfully.\r\n"
                issuper = True
                print(1)
            else:
                with open("user.txt") as fp:
                    datafile = fp.readlines()
                for line in datafile:
                    isfound = False
                    ls = line.split(" ")
                    for x in ls:
                        if username == x:
                            isfound = True
                    if isfound:
                        print(ls)
                        if password == ls[1]:
                            isfound = True
                            isloggin = True
                            message = b"230 login successfully.\r\n"
                            if ls[2] == "super" or ls[2] == "super\n":
                                issuper = True
                                print(2)
                            else:
                                pass
                            break
                        else:
                            message = b"430 Invalid username or password.\r\n"
                            isloggin = False

                    else:
                        message = b"430 Invalid username or password.\r\n"
            client.send(message)

            #
            # if password == "123456" or isano:
            #     isloggin = True
            #     message = b"230 login successfully.\r\n"
            # else:
            #     isloggin = False
            #     message = b"430 Invalid username or password.\r\n"

        elif line[:4] == "TYPE":
            cmd = line[5:].strip()
            if cmd == "I":
                client.send(b"200 Type set to binary.\r\n")

        elif line[:4] == "LIST":
            filename = line[5:]
            if filename == "":
                msg = os.path.dirname(filename)
                client.send(msg.encode() + b"\r\n")
            else:
                msg = os.path.dirname(__file__)
                client.send(msg.encode() + b"\r\n")
            pass
        elif line[:4] == "PWD":

            pass
        elif line[:4] == "FEAT":

            pass
        elif line[:4] == "RMD":

            pass

        elif line[:4] == "HELP":

            pass
        else:
            client.send(b"200 OK\r\n")
            pass

        line = client.recv(1024).decode('ascii').strip()

    if line[:4] == "QUIT":
        client.send(b"221 Goodbye.\r\n")
    else:
        client.send(b" 502 Command not implemented.")
