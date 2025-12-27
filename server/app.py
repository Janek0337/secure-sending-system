from flask import Flask, jsonify, redirect, request, make_response
import DbController as DbController
import DTOs
from pydantic import ValidationError
from http import HTTPStatus
from services.UserService import user_service
from JWT_manager import JWT_manager
from services.MessageService import message_service
import base64

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

        if user_service.user_exists(register_dto.login):
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
    
    jwt_token = {'access-token': jwt_manager.create_token(verification_result, login_dto.login)}

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
        message_dto = DTOs.MessageDTO(**data)
    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    save_status = message_service.save_message(token_data['uid'], message_dto.receiver, message_dto)
    if save_status == HTTPStatus.CREATED:
        res_text = "Success"
    else:
        res_text = "Error"

    return jsonify(res_text), save_status

@app.route("/get-key", methods=["GET"])
def get_key():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        key_request_dto = DTOs.KeyTransferDTO(**data)
    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    key = message_service.get_key_by_login(key_request_dto.login)
    
    if key is None:
        return jsonify(DTOs.KeyTransferDTO(login=key_request_dto.login, key=None).model_dump()), HTTPStatus.NOT_FOUND
    return jsonify(DTOs.KeyTransferDTO(login=key_request_dto.login, key=key).model_dump()), HTTPStatus.OK

if __name__ == '__main__':
    DbController.prepare_database()
    app.run(debug=True, port=5000)