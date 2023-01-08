import subprocess
from tools.json_parsing import final_port_data
import os 


def rustscan(target):
    final_command = f"sudo rustscan -a {target} -- -Pn -O -sV -sC -oX data/scan/nmap.xml"
    print(f'[+] RUNNING COMMAND {final_command}')
    subprocess.run(final_command, shell=True, stdout=subprocess.DEVNULL)
    print(f'[+] PORT SCAN SUCCESSFUL')

    while not os.path.exists("data/scan/nmap.xml"):
        continue
    print("[+] PORT DATA SAVED")
    return final_port_data()
