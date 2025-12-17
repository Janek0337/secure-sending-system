from flask import Flask, jsonify, redirect, request
import DbController as DbController
import DTOs
from pydantic import ValidationError
from http import HTTPStatus
from services.UserService import user_service

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        register_dto = DTOs.RegisterDTO(**data)

        if user_service.register_user(register_dto):
            return jsonify("User created"), HTTPStatus.CREATED
        else:
            return jsonify("Input error"), HTTPStatus.CONFLICT


    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        login_dto = DTOs.LoginDTO(**data)

        if not user_service.verify_login(login_dto):
            return jsonify("Invalid login credentials"), HTTPStatus.FORBIDDEN

        jwt_token = ""

        return jsonify(jwt_token), HTTPStatus.OK
    
    except ValidationError:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

if __name__ == '__main__':
    DbController.prepare_database()
    app.run(debug=True, port=5000)