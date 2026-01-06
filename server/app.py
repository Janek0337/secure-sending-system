from shared import DTOs
from flask import Flask, jsonify, request
import DbController as DbController
from pydantic import ValidationError
from http import HTTPStatus
from services.UserService import user_service
from JWT_manager import JWT_manager
from services.MessageService import message_service
import base64
import shared.utils as utils
from shared.DTOs import MessageDTO

app = Flask(__name__)
jwt_manager = JWT_manager()

def encode_bytes_to_b64(b):
    return base64.b64encode(b).decode('utf-8')

def decode_bytes_from_b64(b):
    return base64.b64decode(b)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        register_dto = DTOs.RegisterDTO(**data)

        if user_service.user_exists(register_dto.username):
            return jsonify("User already exists"), HTTPStatus.CONFLICT

        if user_service.register_user(register_dto):
            return jsonify("User created"), HTTPStatus.CREATED
        else:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        login_dto = DTOs.LoginDTO(**data)

    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST
    
    verification_result = user_service.verify_login(login_dto)
    if not verification_result:
        return jsonify("Invalid login credentials"), HTTPStatus.FORBIDDEN
    
    jwt_token = {'access-token': jwt_manager.create_token(verification_result, login_dto.username)}

    return jsonify(jwt_token), HTTPStatus.OK

@app.route("/message", methods=["POST"])
def send_message():
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        message_dto = DTOs.MessageListDTO(**data)
        list_of_messages = message_dto.message_list
    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    # i assume all messages have the same content, just sent to different people so checking just one message is sufficient
    if utils.verify_message_size(list_of_messages[0]) == HTTPStatus.CONTENT_TOO_LARGE:
        return jsonify("Message too long or attachments too large"), HTTPStatus.CONTENT_TOO_LARGE

    save_status = message_service.save_message(token_data['uid'], list_of_messages)
    if save_status is None:
        return jsonify(None), HTTPStatus.INTERNAL_SERVER_ERROR
    else:
        return jsonify(save_status), HTTPStatus.OK

@app.route("/get-key", methods=["POST"])
def get_key():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        key_request_dto = DTOs.KeyTransferDTO(**data)
    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    keys_dict = message_service.get_key_by_username(key_request_dto)

    return jsonify(DTOs.KeyTransferDTO(key_list=keys_dict).model_dump()), HTTPStatus.OK

@app.route("/get-messages", methods=["POST"])
def get_messages():
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    messages_dto = message_service.get_messages_list(token_data['uid'])
    messag_list = DTOs.MessageListListDTO(
        list_elements=[m.model_dump() for m in messages_dto],
        owner=token_data['username']
    )
    return jsonify(messag_list.model_dump()), HTTPStatus.OK

@app.route("/get-the-message/<int:message_id>", methods=["GET"])
def get_message(message_id):
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    dto = message_service.get_the_message(token_data['username'], message_id)
    if dto == False:
        return jsonify("Not allowed"), HTTPStatus.FORBIDDEN
    return dto.model_dump(), HTTPStatus.OK

@app.route("/mark-read/<int:message_id>", methods=["POST"])
def mark_read(message_id):
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN
    if not message_service.is_user_receiver_of_message(token_data['username'], message_id):
        return jsonify("Not allowed"), HTTPStatus.FORBIDDEN

    if message_service.mark_read(message_id):
        return jsonify("Success"), HTTPStatus.OK
    return jsonify("Unsuccessful update"), HTTPStatus.INTERNAL_SERVER_ERROR

@app.route("/delete-message/<int:message_id>", methods=["DELETE"])
def delete_message(message_id):
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN
    if not message_service.is_user_receiver_of_message(token_data['username'], message_id):
        return jsonify("Not allowed"), HTTPStatus.FORBIDDEN

    if not message_service.delete_message(message_id):
        return jsonify("Error"), HTTPStatus.INTERNAL_SERVER_ERROR

    return jsonify("Success"), HTTPStatus.NO_CONTENT

if __name__ == '__main__':
    DbController.prepare_database()
    app.run(debug=True, port=5000)