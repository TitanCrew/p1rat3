import subprocess
from tools.json_parsing import final_port_data
import os 


def rustscan(target):
    final_command = f"sudo rustscan -a {target} -- -Pn -O -sV -sC -oX data/scan/nmap.xml"
    subprocess.run(final_command, shell=True, stdout=subprocess.DEVNULL)

    while not os.path.exists("data/scan/nmap.xml"):
        continue

    return final_port_data()
