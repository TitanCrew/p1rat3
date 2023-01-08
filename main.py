from flask import Flask, render_template, redirect, request
from tools import port_scan
import os
import socket

app = Flask(__name__)


@app.route("/", methods = ["GET"])
def home():
    return render_template("home/index.html")


@app.route('/', methods = ["POST"])
def submit():
    value = request.form.get('data').strip()
    print(f"[+] GOT REQUEST TO SCAN {value}")
    try:
        target = socket.gethostbyname(value)
        print(f'[+] TARGET RESOLVED {value} -> {target}')
    except:
        print(f'[-] ERROR IN RESOLVING {value}')
        return "Cant resolve host"
    result = port_scan.rustscan(target)
    os.remove("data/scan/nmap.xml")
    return render_template("result/index.html", osInfo = result['os'], portInfo = result['ports'])


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=7000)
