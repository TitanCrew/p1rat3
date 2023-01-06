import subprocess
from tools.json_parsing import final_port_data


def rustscan(target):
    final_command = f"sudo rustscan -a {target} -- -Pn -O -sV -sC -oX data/scan/nmap/initial.xml"
    subprocess.run(final_command, shell=True, stdout=subprocess.DEVNULL)

    return final_port_data()
