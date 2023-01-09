import subprocess
from tools.json_parsing import final_port_data


def rustscan(target):
    final_command = f"sudo rustscan -a {target} -- -Pn -O -sV -oX data/scan/nmap.xml"
    print(f'[+] RUNNING COMMAND {final_command}')
    subprocess.run(final_command, shell=True, stdout=subprocess.DEVNULL)
    print(f'[+] PORT SCAN SUCCESSFUL')

    print("[+] PORT DATA SAVED")
    return final_port_data()
