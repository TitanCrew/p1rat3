import subprocess
import json

def check_subdomain():
    cmd = f'python3 tools/sub404/sub404.py -f data/subdomain_takeover/output_sub_domain | grep -e "Found" -e "Checked" -e "vulnerable" > sub_tmp.txt'

    subprocess.run(cmd,shell=True)