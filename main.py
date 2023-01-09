from flask import Flask, render_template, redirect, request
from tools import port_scan
from tools.wappalyzer import lookup 
import os
import socket
import json
import re

app = Flask(__name__)
wapp = lookup(os.getenv("wappalyzer_api"))

@app.route("/", methods=["GET"])
def home():
    return render_template("home/index.html")


@app.route('/', methods = ["POST"])
def submit():
    value = request.form.get('data').strip()
    print(f"[+] GOT REQUEST TO SCAN {value}")
    try:
        reg = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
        m = re.search(reg, value)
        hostname = m['host']
        port = m['port']
        if port:
            domain = f'{hostname}:{port}'
            print(f'[+] DOMAIN: {domain}')
            target = socket.gethostbyname(domain)
        else:
            domain = hostname
            print(f'[+] DOMAIN: {domain}')
            target = socket.gethostbyname(domain)
        print(f'[+] TARGET RESOLVED {domain} -> {target}')
    except:
        print(f'[-] ERROR IN RESOLVING {value}')
        return "Cant resolve host"
    result = port_scan.rustscan(target)
    wapp_res = wapp.get_stack(value)
    iconMap = json.loads(open("static/map.json").read())
    os.remove("data/scan/nmap.xml")
    return render_template("result/index.html", osInfo = result['os'], portInfo = result['ports'], wapp_res = wapp_res[0]["technologies"], iconMap = iconMap)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
