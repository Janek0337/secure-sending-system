from flask import Flask, render_template, jsonify, redirect, request, flash, url_for, make_response
import requests
import DTOs
import KeyManager
import Ciphrer
from http import HTTPStatus
import os
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)
server_address = "http://127.0.0.1:5000"
key_manager = KeyManager.KeyManager()
ciphrer = Ciphrer.AES_cipherer()

def encode_bytes_to_b64(b):
    return base64.b64encode(b).decode('utf-8')

def decode_bytes_from_b64(b):
    return base64.b64decode(b)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')
    payload = {
        "username": username,
        "password": password
    }
    try:
        res = requests.post(url=server_address+"/login", json=payload)
        my_res = make_response(redirect(url_for('menu')))
        if res.status_code == HTTPStatus.OK:
            print("Udane logowanie")
            token = res.json().get('access-token')
            if token:
                my_res.set_cookie(
                    'access-token',
                    token,
                    # httponly=True, TODO: uncomment later
                    samesite='Lax'
                )
        else:
            print("Nieudane logowanie")

        return my_res

    except requests.exceptions.RequestException as e:
        print("Exception:", e)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template('register.html')
    
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    key_manager.create_key()
    try:
        register_dto = DTOs.RegisterDTO(username=username, password=password, email=email, public_key=key_manager.get_pub_key_text())
        res = requests.post(url=server_address + "/register", json=register_dto.model_dump())
        if res.status_code == HTTPStatus.CREATED:
            flash("Successful registration! You can now log in.", "success")
            return redirect(url_for('login'))
        elif res.status_code == HTTPStatus.CONFLICT:
            flash("User with such username already exists", "error")
            return redirect(url_for('login'))
        else:
            flash("Error has happened", "error")
            return render_template('register.html')
    finally:
        key_manager.save_key(username, password)


@app.route('/message', methods=["GET","POST"])
def message():
    if request.method == "GET":
        return render_template('messenger.html')
    
    receiver = request.form['receiver']
    content = request.form['message']

    res = requests.get(url = server_address + "/get-key", json=DTOs.KeyTransferDTO(username=receiver, key=None).model_dump())
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
        ready_attachment_list.append(((filename, encode_bytes_to_b64(encrypted_data)), encode_bytes_to_b64(encrypted_data_key)))
        
    to_send = DTOs.MessageDTO(
        receiver=receiver,
        content=(encode_bytes_to_b64(encrypted_message), encode_bytes_to_b64(encrypted_message_key)),
        attachments=ready_attachment_list
        )

    token = request.cookies.get('access-token')
    if not token:
        flash("Authentication token is missing!", "error")
        return redirect(url_for('login'))

    cookies = {'access-token': token}

    print(f"Sending: {to_send.model_dump()}")
    res = requests.post(url=server_address + "/message", json=to_send.model_dump(), cookies=cookies)
    if res.status_code == HTTPStatus.CREATED:
        flash(f"Sent message to {receiver}", "success")
    else:
        flash(f"Couldnt send message, code: {res.status_code}", "error")
    return redirect(url_for('menu'))
    
@app.route('/menu', methods=["GET"])
def menu():
    message_list = []
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.post(url=server_address + "/get-messages", cookies=cookies)
    if res.status_code == HTTPStatus.OK:
        try:
            message_list = [DTOs.MessageListElementDTO(**m) for m in res.json()]
            print(f"Lista wiadomosci: {message_list}")
        except Exception as e:
            flash("Error has happened!", "error")
    elif res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't access your messages", "error")
    else:
        flash("Couldn't get your messages", "error")

    return render_template("menu.html", messages=message_list)

if __name__ == "__main__":
    app.run(debug=True, port=3045)