import subprocess
import os
import json
import xmltodict
from concurrent.futures import ThreadPoolExecutor
import os


def run_command(command):
    return subprocess.run(command, shell=True, capture_output=True).stdout


def list_ports(target):
    command = f"rustscan -a {target} -g"

    try:
        ports = json.loads(run_command(command).decode().split('->')[1].strip())
        return ports

    except IndexError:
        exit(os.EX_DATAERR)


def check_port(target, port):
    command = f"rustscan -a {target} -p {port} -- -sC"