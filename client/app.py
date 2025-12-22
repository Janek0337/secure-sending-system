from flask import Flask, render_template, jsonify, redirect, request
import requests

app = Flask(__name__)
server_address = "http://127.0.0.1:5000"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    print(f"Metoda: {request.method}")
    if request.method == "GET":
        return render_template('login.html')

    login = request.form.get('login')
    password = request.form.get('password')
    payload = {
        "login": login,
        "password": password
    }
    try:
        res = requests.post(url=server_address+"/login", json=payload)
        if res.status_code == 200:
            print("Udane logowanie")
        else:
            print("Nieudane logowanie")

    except requests.exceptions.RequestException as e:
        print("Exception:", e)

    return f"Koniec"

@app.route('/register')
def register():
    return render_template('register.html')

if __name__ == "__main__":
    app.run(debug=True, port=3045)