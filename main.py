from flask import Flask, render_template, redirect, request
from tools import port_scan

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return render_template("home/index.html")


@app.route('/result', methods=["POST"])
def submit():
    value = request.form.get('data')
    result = port_scan.rustscan(value)
    print(result)
    return render_template("result/index.html", osInfo=result['os'], portInfo=result['ports'])


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
