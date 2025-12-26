from flask import Flask, jsonify, redirect, request, make_response
import DbController as DbController
import DTOs
from pydantic import ValidationError
from http import HTTPStatus
from services.UserService import user_service
from JWT_manager import JWT_manager
from services.MessageService import message_service
app = Flask(__name__)
jwt_manager = JWT_manager()

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
    if verification_result == False:
        return jsonify("Invalid login credentials"), HTTPStatus.FORBIDDEN
    
    jwt_token = jwt_manager.create_token(verification_result, login_dto.login)

    response = make_response(jsonify(jwt_token), HTTPStatus.OK)
    response.set_cookie(
        'access_token',
        jwt_token,
        httponly=True,
        # secure=True, TODO: uncomment later
        samesite='Lax'
    )

    return response
"""
@app.route("/message", methods=["POST"])
def send_message():
    token = request.cookies.get('access_token')
    if not token or not jwt_manager.validate_jwt_token(token):
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN
"""
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