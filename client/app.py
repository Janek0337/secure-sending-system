from flask import Flask, render_template, redirect, request, flash, url_for, make_response, jsonify
import requests
from shared import DTOs
import KeyManager
import Ciphrer
from http import HTTPStatus
import os
import base64
from datetime import datetime
from shared.utils import is_password_secure

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

        if not key_manager.load_key(username, password):
            flash("Missing or faulty key")
            return redirect(url_for('register'))
        return my_res

    except requests.exceptions.RequestException as e:
        print("Exception:", e)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template('register.html')
    
    username = request.form['username']
    password = request.form['password']
    confirmed_password = request.form['confirmPassword']
    email = request.form['email']

    if password != confirmed_password:
        flash("Password and confirmed password are different. Did not register.", "error")
        return redirect(url_for('register'))

    if not is_password_secure(password):
        flash("Password is not secure enough. Did not register.", "error")
        return redirect(url_for('register'))

    key_manager.create_key()
    try:
        register_dto = DTOs.RegisterDTO(username=username, password=password, email=email, public_key=key_manager.get_pub_key_text())
        res = requests.post(url=server_address + "/register", json=register_dto.model_dump())
        if res.status_code == HTTPStatus.CREATED:
            flash("Successful registration! You can now log in.", "success")
            return redirect(url_for('login'))
        elif res.status_code == HTTPStatus.CONFLICT:
            flash("User with such username already exists.", "error")
            return redirect(url_for('register'))
        else:
            flash("Error has happened.", "error")
            return redirect(url_for('register'))
    finally:
        key_manager.save_key(username, password)


@app.route('/message', methods=["GET","POST"])
def message():
    if request.method == "GET":
        return render_template('messenger.html')
    
    receiver = request.form['receiver']
    content = request.form['message']

    res = requests.post(url = server_address + "/get-key", json=DTOs.KeyTransferDTO(username=receiver, key=None).model_dump())
    if res.status_code == HTTPStatus.OK:
        receiver_key = res.json()['key']
    elif res.status_code == HTTPStatus.NOT_FOUND:
        return f"Receiver '{receiver}' not found", HTTPStatus.NOT_FOUND
    else:
        return f"Server error", HTTPStatus.INTERNAL_SERVER_ERROR

    message_hash = key_manager.hash_and_sign_data(content.encode('utf-8'))
    encrypted_message, message_key = ciphrer.encrypt_data(content.encode("utf-8")) # aes
    encrypted_message_key = key_manager.encrypt_data(message_key, receiver_key.encode("utf-8")) # rsa

    preprocessed_attachments = [(f.filename, f.read()) for f in request.files.getlist('attachments') if f.filename]
    ready_attachment_list = []
    for attachment in preprocessed_attachments:
        data = attachment[1]
        attachment_hash = key_manager.hash_and_sign_data(data)
        encrypted_data, data_key = ciphrer.encrypt_data(data) # aes
        encrypted_filename, _ = ciphrer.encrypt_data(attachment[0].encode("utf-8"), data_key)
        encrypted_data_key = key_manager.encrypt_data(data_key, receiver_key) # rsa
        ready_attachment_list.append(((encode_bytes_to_b64(encrypted_filename),
                                       encode_bytes_to_b64(encrypted_data)),
                                      encode_bytes_to_b64(encrypted_data_key),
                                    attachment_hash
                                     ))
        
    to_send = DTOs.MessageDTO(
        receiver=receiver,
        content=(encode_bytes_to_b64(encrypted_message), encode_bytes_to_b64(encrypted_message_key), message_hash),
        attachments=ready_attachment_list
        )

    token = request.cookies.get('access-token')
    if not token:
        return jsonify("Please log in again."), HTTPStatus.FORBIDDEN

    cookies = {'access-token': token}
    res = requests.post(url=server_address + "/message", json=to_send.model_dump(), cookies=cookies)
    if res.status_code == HTTPStatus.CREATED:
        flash(f"Sent message to {receiver}", "success")
        return redirect(url_for('menu'))
    elif res.status_code == HTTPStatus.CONTENT_TOO_LARGE:
        flash("Either message is too long or attachments too large. Did not send the message", "error")
        return redirect(url_for('message'))
    else:
        flash(f"Couldn't send message, code: {res.status_code}", "error")
        return redirect(url_for('message'))
    
@app.route('/menu', methods=["GET"])
def menu():
    message_list = []
    owner = "Unknown"
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.post(url=server_address + "/get-messages", cookies=cookies)
    if res.status_code == HTTPStatus.OK:
        try:
            response = res.json()
            message_list = [DTOs.MessageListElementDTO(**m) for m in response.get('list_elements',[])]
            owner = response.get('owner', 'Unknown')
        except Exception as e:
            flash("Error has happened!", "error")
    else:
        flash("Couldn't access your messages", "error")

    return render_template("menu.html", messages=message_list, owner=owner)

@app.route('/get-the-message/<int:message_id>', methods=["GET"])
def get_the_message(message_id):
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    if key_manager.key is None:
        flash("Please log in again.", "error")
        return redirect(url_for('login'))
    res = requests.get(url=f"{server_address}/get-the-message/{message_id}", cookies=cookies)
    if res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't access your message.", "error")
        return redirect(url_for('menu'))

    dto = DTOs.GetMessageDTO(**res.json())
    # content
    content_bytes = decode_bytes_from_b64(dto.content[0]), decode_bytes_from_b64(dto.content[1])
    decrypted_content_key = key_manager.decrypt_data(content_bytes[1])
    deciphered_content = ciphrer.decrypt_data(content_bytes[0], decrypted_content_key)
    message_hash = dto.content[2]

    # attachments
    good_attachments = []
    for a in dto.attachments:
        bytes_filename = decode_bytes_from_b64(a[0][0])
        bytes_attachment = decode_bytes_from_b64(a[0][1])
        bytes_key = decode_bytes_from_b64(a[1])
        attachment_hash = a[2]

        decrypted_key = key_manager.decrypt_data(bytes_key)
        deciphered_filename = ciphrer.decrypt_data(bytes_filename, decrypted_key)
        deciphered_attachment = ciphrer.decrypt_data(bytes_attachment, decrypted_key)

        good_attachments.append(
            (deciphered_filename, base64.b64encode(deciphered_attachment).decode('utf-8'), attachment_hash,
             deciphered_attachment))

    timestamp = dto.date_sent
    dt_obj = datetime.fromtimestamp(float(timestamp))
    date_str = datetime.strftime(dt_obj, "%d/%m/%Y %H:%M:%S")

    message_data = DTOs.ViewMessage(
        message_id=message_id,
        sender=dto.sender,
        content=deciphered_content.decode('utf-8'),
        attachments=good_attachments,
        date_sent=date_str,
        content_hash=message_hash
    )
    print(f"Hash: {message_hash}")
    verified = False
    username = dto.sender
    res = requests.post(url=f"{server_address}/get-key",
                        json=DTOs.KeyTransferDTO(username=username, key=None).model_dump())
    if res.status_code == HTTPStatus.OK:
        key = res.json().get("key")
        verified = key_manager.verify_signature(
            data=deciphered_content,
            signature=decode_bytes_from_b64(message_hash),
            public_key_str=key
        )

        if verified:
            for a in good_attachments:
                if not key_manager.verify_signature(
                        data=a[3],
                        signature=decode_bytes_from_b64(a[2]),
                        public_key_str=key
                ):
                    verified = False
                    break
    else:
        flash("Could not verify authenticity of the message", "error")

    return render_template('message_view.html', data=message_data, verified=verified)

@app.route('/mark-read/<int:message_id>', methods=["POST"])
def mark_read(message_id):
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.post(url=f"{server_address}/mark-read/{message_id}", cookies=cookies)
    if res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't apply changes. Please log in again.", "error")
        return redirect(url_for('login'))
    elif res.status_code == HTTPStatus.OK:
        flash("Message marked as read", "success")
        return redirect(url_for('menu'))
    else:
        flash("Error. Did not apply changes.")
        return redirect(url_for('menu'))

@app.route("/delete-message/<int:message_id>", methods=["POST"])
def delete_message(message_id):
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.delete(url=f"{server_address}/delete-message/{message_id}", cookies=cookies)
    if res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't apply changes. Please log in again.", "error")
        return redirect(url_for('login'))
    elif res.status_code == HTTPStatus.NO_CONTENT:
        flash("Message deleted.", "success")
        return redirect(url_for('menu'))
    else:
        flash(f"Error. Did not delete. Status code: {res.status_code}")
        return redirect(url_for('menu'))

@app.route("/get-key", methods=["POST"])
def get_key():
    username = request.form.get("sender")
    res = requests.post(url=f"{server_address}/get-key", json=DTOs.KeyTransferDTO(username=username, key=None).model_dump())
    if res.status_code == HTTPStatus.OK:
        key = res.json().get("key")
        filename = f"keys/public_key_{username}.pem"
        with open(filename, "wb") as f:
            f.write(key.encode("utf-8"))
            flash(f"Key downloaded to file: {filename}", "success")
            return redirect(url_for('menu'))
    else:
        flash("Error. Did not download key.")
        return redirect(url_for('menu'))

if __name__ == "__main__":
    app.run(debug=True, port=3045)