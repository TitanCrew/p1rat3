from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return render_template("home/index.html")


@app.route('/submit', methods=["POST"])
def submit():
    values = request.form.get('data')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
