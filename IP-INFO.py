VERSION = '1.1.1'
R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import socket
from ipaddress import ip_address
import requests
import json
import sys

import pyfiglet
from rich.console import Console
from rich.table import Table

from utils import extract_json_data, threadpool_executer

print(f'''\n{Y}                            __
        !! !!!!!        !! !  \   ! !!!!! !!!!!!!
        !! !!!!!        !! !   \  ! !!    !     !
        !! !    ------- !! !    \ ! !!!   !     !
        !! !            !! !     \! !!    !!!!!!!
''')


print(f'\n{G}[>] {C}Created By   : {G}Crizzy')
print(f'{G}[>] {C}Version      : {G}{VERSION}\n')
print(f'{R}The software is for INFORMATIONAL purposes ONLY, the author does not take ANY RESPONSIBILITY for the use you make of the software\n')
print(f'''\n
    {R}-{W}To find the IP of any site, select {R}1{W}; {C}<--
    {R}-{W}To find information about an IP, select {R}2{W}; {C}<--
    {R}-{W}To scan open ports, select {R}3{W}; {C}<--
\n''')

choose = input(f'Enter the number corresponding to the software you want to use --->  {G}')
if choose == "1":
    print(f'\nYou have chosen the number: {R}1\n')
    host_name = input(f"{C}Enter the website address: {G}")
    print(f'\n {G}The {host_name} IP address is: {R}{socket.gethostbyname(host_name)}\n')

elif choose == "2":
    print(f'\nYou have chosen the number: {R}2\n')
    host_name = input(f"{C}Enter the IP to scan: {G}")
    try:
        socket.inet_aton(host_name)
        print(f"\n{Y}Valid IP address\n")
        if(ip_address(host_name).is_private):
            print(f"{C}The IP is Private")
        else:
            print(f"{C}The IP is Public")
            print(f"{Y}")
            request_url = 'https://geolocation-db.com/jsonp/' + host_name
            response = requests.get(request_url)
            result = response.content.decode()
            result = result.split("(")[1].strip(")")
            result  = json.loads(result)
            print(result)
    except socket.error:
            print(f"\n{R}Invalid IP\n")

elif choose == "3":
    print(f'\nYou have chosen the number: {R}3\n')
    print(f'\nCopyright (c) 2020 Michele Saba')
    print(f'''\nPermission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.\n''')
    console = Console()
    class CrizzyScan:

        PORTS_DATA_FILE = "./common_ports.json"

        def __init__(self):
            self.open_ports = []
            self.ports_info = {}
            self.remote_host = ""

        def get_ports_info(self):
            data = extract_json_data(CrizzyScan.PORTS_DATA_FILE)
            self.ports_info = {int(k): v for (k, v) in data.items()}

        @staticmethod
        def get_host_ip_addr(target):
            try:
                ip_addr = socket.gethostbyname(target)
            except socket.gaierror as e:
                print(f"There was an error... {e}")
                sys.exit()
            console.print(f"\nIP Address acquired: [bold blue]{ip_addr}[/bold blue]")
            return ip_addr

        def scan_port(self, port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            conn_status = sock.connect_ex((self.remote_host, port))
            if conn_status == 0:
                self.open_ports.append(port)
            sock.close()

        def show_completion_message(self):
            print()
            if self.open_ports:
                console.print("Scan Completed. Open Ports:", style="bold blue")
                table = Table(show_header=True, header_style="bold green")
                table.add_column("PORT", style="blue")
                table.add_column("STATE", style="blue", justify="center")
                table.add_column("SERVICE", style="blue")
                for port in self.open_ports:
                    table.add_row(str(port), "OPEN", self.ports_info[port])
                console.print(table)
            else:
                console.print("No Open Ports Found on Target.", style="bold magenta")

        @staticmethod
        def show_startup_message():
            ascii_art = pyfiglet.figlet_format("# CrizzyScan #")
            console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
            console.print("!" * 55, style="bold green")
            console.print(
                ">" * 12, "MultiThread TCP Port Scanner", "<" * 13, style="bold black"
            )
            console.print("!" * 55, style="bold green")
            print()

        def initialize(self):
            self.show_startup_message()
            self.get_ports_info()
            try:
                target = input("Insert target: ")
            except KeyboardInterrupt:
                console.print("\nI'm leaving. Exiting.", style="bold red")
                sys.exit()
            self.remote_host = self.get_host_ip_addr(target)
            try:
                input("\nCrizzyScan is ready. Press ENTER to run the scanner.")
            except KeyboardInterrupt:
                console.print("\nI'm leaving. Exiting.", style="bold red")
                sys.exit()
            else:
                self.run()

        def run(self):
            threadpool_executer(
                self.scan_port, self.ports_info.keys(), len(self.ports_info.keys())
            )
            self.show_completion_message()



    if __name__ == "__main__":
        CrizzyScan = CrizzyScan()
        CrizzyScan.initialize()
