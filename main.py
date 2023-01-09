from flask import Flask, render_template, redirect, request
from tools import port_scan, xss, cve_search
from tools.wappalyzer import lookup
import socket
import json
import re

app = Flask(__name__)
wapp = lookup("V27thSllZy85ohAn9DYi83xlQjICTGS65f2ZKOhk")


@app.route("/", methods=["GET"])
def home():
    return render_template("home/index.html")


@app.route('/', methods=["POST"])
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
    except Exception as e:
        print(f'[-] ERROR IN RESOLVING {value}')
        print(e)
        return "Cant resolve host"

    print("[+] PORT SCAN STARTED")
    result = port_scan.rustscan(target)
    print("[+] TECH STACK SCAN STARTED")
    wapp_res = wapp.get_stack(value)
    print("[+] VULNERABILITY SCAN STARTED")
    cve_search.list_vuln()
    print("[+] XSS SCAN STARTED")
    xss.check_xss(value)

    iconMap = json.loads(open("/p1rat3/static/map.json").read())
    getXSS = json.loads(open("/p1rat3/data/xss/get.json").read())
    postXSS = json.loads(open("/p1rat3/data/xss/post.json").read())

    return render_template("result/index.html", osInfo=result['os'], portInfo=result['ports'],
                           wapp_res=wapp_res[0]["technologies"], iconMap=iconMap, getXSS=getXSS, postXSS=postXSS)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=6969)
