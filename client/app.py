from flask import Flask, render_template, jsonify, redirect, request, flash, url_for
import requests
import DTOs
import KeyManager
import Ciphrer
from http import HTTPStatus
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
server_address = "http://127.0.0.1:5000"
key_manager = KeyManager.KeyManager()
ciphrer = Ciphrer.AES_cipherer()

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=["GET", "POST"])
def login():
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
        if res.status_code == HTTPStatus.OK:
            print("Udane logowanie")
        else:
            print("Nieudane logowanie")

    except requests.exceptions.RequestException as e:
        print("Exception:", e)

    return f"Koniec"

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template('register.html')
    
    login = request.form['login']
    password = request.form['password']
    email = request.form['email']

    key_manager.create_key()
    try:
        register_dto = DTOs.RegisterDTO(login=login, password=password, email=email, public_key=key_manager.get_pub_key_text())
        res = requests.post(url=server_address + "/register", json=register_dto.model_dump())
        if res.status_code == HTTPStatus.CREATED:
            flash("Successful registration! You can now log in.", "success")
            return redirect(url_for('login'))
        elif res.status_code == HTTPStatus.CONFLICT:
            flash("User with such login already exists", "error")
            return redirect(url_for('login'))
        else:
            flash("Error has happened", "error")
            return render_template('register.html')
    finally:
        key_manager.save_key(login, password)


@app.route('/message', methods=["GET","POST"])
def message():
    if request.method == "GET":
        return render_template('messenger.html')
    
    receiver = request.form['receiver']
    content = request.form['message']

    res = requests.get(url = server_address + "/get-key", json=DTOs.KeyTransferDTO(login=receiver, key=None).model_dump())
    if res.status_code == HTTPStatus.OK:
        receiver_key = res.json()['key']
    elif res.status_code == HTTPStatus.NOT_FOUND:
        return f"Receiver '{receiver}' not found", HTTPStatus.NOT_FOUND
    else:
        return f"Server error", HTTPStatus.INTERNAL_SERVER_ERROR

    encrypted_message, message_key = ciphrer.encrypt_data(content.encode("utf-8")) # aes
    encrypted_message_key = key_manager.encrypt_data(message_key, receiver_key.encode("utf-8")) # rsa

    preprocessed_attachments = [(f.filename, f.read()) for f in request.files.getlist('attachments') if f.filename]
    ready_attachment_list = []
    for attachment in preprocessed_attachments:
        filename = attachment[0]
        data = attachment[1]
        encrypted_data, data_key = ciphrer.encrypt_data(data) # aes
        encrypted_data_key = key_manager.encrypt_data(data_key, receiver_key) # rsa
        ready_attachment_list.append(((filename, encrypted_data), encrypted_data_key))
        
    to_send = DTOs.MessageDTO(
        receiver=receiver,
        content=(encrypted_message, encrypted_message_key),
        attachments=ready_attachment_list
        )
    
    print(f"Sending: {jsonify(to_send)}")
    res = requests.post(url = server_address + "/message", json = jsonify(to_send))
    #if res.status_code == 200:
    

if __name__ == "__main__":
    app.run(debug=True, port=3045)