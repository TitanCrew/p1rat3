from flask import Flask, render_template, redirect, request
from tools import nmap 

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return render_template("home/index.html")

@app.route('/result', methods=["POST"])
def submit():
    value = request.form.get('data')
    # nmap.run_command(nmap.parse({"sS": "0","sU": "0","sV": "0","O": "0","target": f"{value}"}))
    result = nmap.parse_output()
    return render_template("result/index.html", osInfo = result[1], portInfo = result[0])

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
