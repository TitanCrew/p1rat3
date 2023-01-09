import subprocess
import json

def check_subdomain():
    cmd = f'python3 /p1rat3/tools/sub404.py -f /p1rat3/data/subdomain_takeover/output_sub_domain | grep -e "Found" -e "Checked" -e "vulnerable" > /p1rat3/data/subdomain_takeover/sub_tmp.txt'

    subprocess.run(cmd,shell=True)