from flask import Flask, render_template, redirect, request, flash, url_for, make_response
import requests
from pydantic import ValidationError

from shared import DTOs
import client.KeyManager as KeyManager
from http import HTTPStatus
import sys
import ipaddress
import base64
from datetime import datetime

from shared.DTOs import MessageDTO
from shared.TOTP_manager import totp_manager
from shared.utils import is_password_secure
import shared.utils as utils
from shared.Ciphrer import ciphrer
import logging
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s at line %(lineno)d: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

if len(sys.argv) > 2:
    logger.error("Invalid args count")
    exit(1)

def validate_address(address):
    try:
        host, port = address.split(":")
        ipaddress.ip_address(host)

        return 1 <= int(port) <= 65535
    except ValueError:
        logger.error(f"{address} is not a valid address")
        return False


new_address = sys.argv[1]
address = f"{"127.0.0.1:5000" if not validate_address(new_address) else new_address}"

def get_protocol(address):
    try:
        url = f"https://{address}"
        res = requests.get(f"{url}/hello", verify=False, timeout=2)
        if res.status_code == HTTPStatus.OK:
            return url
    except requests.exceptions.RequestException:
        pass
    return f"http://{address}"

server_address = get_protocol(address)
logger.info(f"Connecting to server at {server_address}")
key_manager = KeyManager.KeyManager()

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

    dto = DTOs.LoginDTO(
        username=username,
        password=password
    )

    res = requests.post(url=f"{server_address}/login", json=dto.model_dump(), verify=False)
    my_res = make_response(redirect(url_for('verify_totp')))
    if res.status_code == HTTPStatus.OK:
        print("Successful login")
        token = res.json().get('access-token')
        if token:
            my_res.set_cookie(
                'access-token',
                token,
                httponly=True,
                samesite='Lax'
            )
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
    else:
        print("Unsuccessful login")

    if not key_manager.load_key(username, password):
        flash("Missing or faulty key")
        return redirect(url_for('register'))
    return my_res

@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    if request.method == "GET":
        return render_template("totp.html")

    token = request.cookies.get('access-token')
    if not token:
        flash("Please log in again.", "error")
        return redirect(url_for('login'))
    cookies = {'access-token': token}

    code = request.form.get('totp')
    res = requests.post(url=f"{server_address}/verify-totp", json={"code" : code}, cookies=cookies, verify=False)
    if res.status_code == HTTPStatus.OK:
        token = res.json().get('token')
        if token:
            my_res = make_response(redirect(url_for('menu')))
            my_res.set_cookie(
                'access-token',
                token,
                httponly=True,
                samesite='Lax'
            )
            return my_res
        else:
            flash("Server error", "error"), HTTPStatus.INTERNAL_SERVER_ERROR
    elif res.status_code == HTTPStatus.FORBIDDEN:
        flash("Wrong code. Try again?", "error")
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
    else:
        flash("Error", "error")

    return redirect(url_for('verify_totp'))

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

    if not utils.verify_username(username):
        flash("Username does not comply with username requirements stated below.")
        return redirect(url_for('register'))

    key_manager.create_key()
    register_dto = DTOs.RegisterDTO(username=username, password=password, email=email, public_key=key_manager.get_pub_key_text())
    res = requests.post(url=f"{server_address}/register", json=register_dto.model_dump(), verify=False)
    if res.status_code == HTTPStatus.CREATED:
        data = res.json()
        key_manager.save_key(username, password)
        img_data_base64 = totp_manager.generate_qr_code(data['secret'], username)
        flash(f"Success. Now you can log in as \"{username}\"")

        return render_template('qr_code.html', qr_code_data=img_data_base64, username=username)

    elif res.status_code == HTTPStatus.CONFLICT:
        flash("Either username or email address already in use. Did not register.", "error")
        return redirect(url_for('register'))
    elif res.status_code == HTTPStatus.BAD_REQUEST:
        flash("Credentials do not meet requirements. Did not register.", "error")
        return redirect(url_for('register'))
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('register'))
    else:
        flash("Error has happened. Did not register.", "error")
        return redirect(url_for('register'))

@app.route('/message', methods=["GET","POST"])
def message():
    if request.method == "GET":
        return render_template('messenger.html')

    token = request.cookies.get('access-token')
    if not token:
        flash("Please log in again.", "error")
        return redirect(url_for('login'))
    cookies = {'access-token': token}

    receivers = request.form['receiver'].split(',')
    receivers = [r.strip() for r in receivers]
    content = request.form['message']

    key_res = requests.post(url = server_address + "/get-key", json=DTOs.KeyTransferDTO(
        key_list={r : None for r in receivers}).model_dump(), verify=False
                )
    if key_res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {key_res.json().get('limit')}", "error")
        return redirect(url_for('message'))
    try:
        data = key_res.json()
        keys = DTOs.KeyTransferDTO(**data)
    except ValidationError as e:
        logger.error(f"Validation error: {e.json()}")
        flash("Key error happened", "error")
        return redirect(url_for('message'))

    list_of_messages: list[MessageDTO] = []
    for receiver in receivers:
        receiver_key = keys.key_list.get(receiver)
        if receiver_key is None:
            flash(f"Could not send message to \"{receiver}\" (no key)", "error")
            continue

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
            encrypted_data_key = key_manager.encrypt_data(data_key, receiver_key.encode("utf-8")) # rsa
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

        if utils.verify_message_size(to_send) == HTTPStatus.CONTENT_TOO_LARGE:
            flash("Either message is too long or attachments too large. Did not send the message", "error")
            return redirect(url_for('message'))

        list_of_messages.append(to_send)
    
    if not list_of_messages:
        flash("No messages were sent.", "error")
        return redirect(url_for('message'))

    res = requests.post(url=f"{server_address}/message", json=DTOs.MessageListDTO(message_list=list_of_messages).model_dump(),
                        cookies=cookies, verify=False)
    if res.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
        flash("Server error. Please try again.", "error")
        return redirect(url_for('message'))
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('message'))
    elif res.status_code == HTTPStatus.CONTENT_TOO_LARGE:
        flash("Content too large", "error")
        return redirect(url_for('message'))

    try:
        result_dict = res.json()
    except (requests.exceptions.JSONDecodeError, ValidationError):
        flash("Failed to decode server response.", "error")
        return redirect(url_for('message'))

    successful = [name for name, status in result_dict.items() if status]
    failed = [name for name, status in result_dict.items() if not status]

    if successful:
        flash(f"Successfully sent to: {', '.join(successful)}", "success")
    if failed:
        flash(f"Failed to send to: {', '.join(failed)}", "error")
    return redirect(url_for('menu'))

@app.route('/menu', methods=["GET"])
def menu():
    message_list = []
    owner = "Unknown"
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.post(url=server_address + "/get-messages", cookies=cookies, verify=False)
    if res.status_code == HTTPStatus.OK:
        try:
            response = res.json()
            message_list = [DTOs.MessageListElementDTO(**m) for m in response.get('list_elements',[])]
            owner = response.get('owner', 'Unknown')
        except Exception as e:
            flash("Error has happened!", "error")
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('menu'))
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
    res = requests.get(url=f"{server_address}/get-the-message/{message_id}", cookies=cookies, verify=False)
    if res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't access your message.", "error")
        return redirect(url_for('menu'))
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
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
    verified = False
    username = dto.sender
    res = requests.post(url=f"{server_address}/get-key", json=DTOs.KeyTransferDTO(
        key_list={username : None}).model_dump(), verify=False)
    if res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('menu'))

    try:
        data = res.json()
        dto = DTOs.KeyTransferDTO(**data)
        if dto.key_list[username] is not None:
            verified = key_manager.verify_signature(
                data=deciphered_content,
                signature=decode_bytes_from_b64(message_hash),
                public_key_str=dto.key_list[username]
            )

            if verified:
                for a in good_attachments:
                    if not key_manager.verify_signature(
                            data=a[3],
                            signature=decode_bytes_from_b64(a[2]),
                            public_key_str=dto.key_list[username]
                    ):
                        verified = False
                        break
        else:
            flash("Could not verify authenticity of the message", "error")
    except ValidationError as e:
        print("Validation error:", e.json())

    return render_template('message_view.html', data=message_data, verified=verified)

@app.route('/mark-read/<int:message_id>', methods=["POST"])
def mark_read(message_id):
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.post(url=f"{server_address}/mark-read/{message_id}", cookies=cookies, verify=False)
    if res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't apply changes. Please log in again.", "error")
        return redirect(url_for('login'))
    elif res.status_code == HTTPStatus.OK:
        flash("Message marked as read", "success")
        return redirect(url_for('menu'))
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('menu'))
    else:
        flash("Error. Did not apply changes.")
        return redirect(url_for('menu'))

@app.route("/delete-message/<int:message_id>", methods=["POST"])
def delete_message(message_id):
    token = request.cookies.get('access-token')
    cookies = {'access-token': token}
    res = requests.delete(url=f"{server_address}/delete-message/{message_id}", cookies=cookies, verify=False)
    if res.status_code == HTTPStatus.FORBIDDEN:
        flash("Couldn't apply changes. Please log in again.", "error")
        return redirect(url_for('login'))
    elif res.status_code == HTTPStatus.NO_CONTENT:
        flash("Message deleted.", "success")
        return redirect(url_for('menu'))
    elif res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('menu'))
    else:
        flash(f"Error. Did not delete. Status code: {res.status_code}")
        return redirect(url_for('menu'))

@app.route("/get-key", methods=["POST"])
def get_key():
    username = request.form.get("sender")
    res = requests.post(url=f"{server_address}/get-key", json=DTOs.KeyTransferDTO(
        key_list={username: None}).model_dump(), verify=False)
    if res.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        flash(f"Too many requests: {res.json().get('limit')}", "error")
        return redirect(url_for('menu'))
    try:
        data = res.json()
        dto = DTOs.KeyTransferDTO(**data)
        key = dto.key_list[username]

        if key is None:
            flash("Error. Did not download key.")
            return redirect(url_for('menu'))

        filename = f"client/keys/public_key_{username}.pem"
        with open(filename, "wb") as f:
            f.write(key.encode("utf-8"))
            flash(f"Key downloaded to file: {filename}", "success")
            return redirect(url_for('menu'))
    except ValidationError as e:
        print("Validation error:", e.json())

if __name__ == "__main__":
    app.run(debug=True, port=3045)