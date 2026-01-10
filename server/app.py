from shared import DTOs
from flask import Flask, jsonify, request
import server.DbController as DbController
from pydantic import ValidationError
from http import HTTPStatus
from server.services.UserService import user_service
from server.JWT_manager import JWT_manager
from server.services.MessageService import message_service
import base64
import shared.utils as utils
from shared.TOTP_manager import totp_manager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 35 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s at line %(lineno)d: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

jwt_manager = JWT_manager()
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1 per second"]
)
logger = logging.getLogger(__name__)

@app.errorhandler(HTTPStatus.TOO_MANY_REQUESTS)
def rate_limit_handler(e):
    logger.info("Rate limit exceeded")
    return jsonify({"limit": e.description()}), HTTPStatus.TOO_MANY_REQUESTS

def encode_bytes_to_b64(b):
    return base64.b64encode(b).decode('utf-8')

def decode_bytes_from_b64(b):
    return base64.b64decode(b)

@app.route('/register', methods=['POST'])
@limiter.limit("1 per minute", override_defaults=True)
def register():
    try:
        data = request.get_json(silent=True)
        if data is None:
            logger.error("Bad request structure")
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        register_dto = DTOs.RegisterDTO(**data)

        register_result = user_service.register_user(register_dto)
        if isinstance(register_result, HTTPStatus):
            if register_result == HTTPStatus.BAD_REQUEST:
                logger.info("Unacceptable credentials")
                return jsonify("Invalid input"), HTTPStatus.BAD_REQUEST
            elif register_result == HTTPStatus.CONFLICT:
                logger.info("Credentials already in use")
                return jsonify("Either username or email already in use"), HTTPStatus.CONFLICT
        else:
            return jsonify({"secret": register_result}), HTTPStatus.CREATED

    except ValidationError:
        logger.error("Validation error")
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

@app.route('/login', methods=['POST'])
@limiter.limit("1 per second", override_defaults=True)
def login():
    try:
        data = request.get_json(silent=True)
        if data is None:
            logging.info("Invalid request")
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        login_dto = DTOs.LoginDTO(**data)

    except ValidationError:
        logger.error("Validation error")
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST
    
    verification_result = user_service.verify_login(login_dto)
    if not verification_result:
        logger.info("Invalid login credentials")
        return jsonify("Invalid login credentials"), HTTPStatus.FORBIDDEN
    
    jwt_token = {'access-token': jwt_manager.create_token(verification_result, login_dto.username, False)}

    logger.info("Successfully log in")
    return jsonify(jwt_token), HTTPStatus.OK

@app.route("/verify-totp", methods=["POST"])
def verify_totp():
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token, False)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    data = request.get_json(silent=True)
    if data is None or 'code' not in data:
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    intended_code = totp_manager.count_totp_code(user_service.get_secret(token_data['uid']))
    given_code = data['code']

    if given_code in intended_code:
        logger.info("Good code")
        return jsonify({"token" : jwt_manager.create_token(token_data['uid'], token_data['username'], True)}), HTTPStatus.OK
    else:
        logger.info("Bad code")
        return jsonify("Bad code bruh"), HTTPStatus.FORBIDDEN

@app.route("/message", methods=["POST"])
def send_message():
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token, True)
    if token_data is None:
        logger.info("Invalid token")
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    try:
        data = request.get_json(silent=True)
        if data is None:
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        message_dto = DTOs.MessageListDTO(**data)
        list_of_messages = message_dto.message_list
    except ValidationError:
        logger.error("Validation error")
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    # i assume all messages have the same content, just sent to different people so checking just one message is sufficient
    if utils.verify_message_size(list_of_messages[0]) == HTTPStatus.CONTENT_TOO_LARGE:
        return jsonify("Message too long or attachments too large"), HTTPStatus.CONTENT_TOO_LARGE

    save_status = message_service.save_message(token_data['uid'], list_of_messages)
    if save_status is None:
        logger.error("Could not save message")
        return jsonify(None), HTTPStatus.INTERNAL_SERVER_ERROR
    else:
        logger.info("Message sent")
        return jsonify(save_status), HTTPStatus.OK

@app.route("/get-key", methods=["POST"])
def get_key():
    try:
        data = request.get_json(silent=True)
        if data is None:
            logger.info("Input error")
            return jsonify("Input error"), HTTPStatus.BAD_REQUEST
        key_request_dto = DTOs.KeyTransferDTO(**data)
    except ValidationError:
        logger.error("Validation error")
        return jsonify("Input error"), HTTPStatus.BAD_REQUEST

    keys_dict = message_service.get_key_by_username(key_request_dto)

    return jsonify(DTOs.KeyTransferDTO(key_list=keys_dict).model_dump()), HTTPStatus.OK

@app.route("/get-messages", methods=["POST"])
def get_messages():
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token, True)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    messages_dto = message_service.get_messages_list(token_data['uid'])
    messag_list = DTOs.MessageListListDTO(
        list_elements=[m.model_dump() for m in messages_dto],
        owner=token_data['username']
    )
    logger.info("Successfully got messages")
    return jsonify(messag_list.model_dump()), HTTPStatus.OK

@app.route("/get-the-message/<int:message_id>", methods=["GET"])
def get_message(message_id):
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token, True)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN

    dto = message_service.get_the_message(token_data['username'], message_id)
    if dto == False:
        return jsonify("Not allowed"), HTTPStatus.FORBIDDEN
    return dto.model_dump(), HTTPStatus.OK

@app.route("/mark-read/<int:message_id>", methods=["POST"])
def mark_read(message_id):
    token = request.cookies.get('access-token')
    token_data = jwt_manager.validate_jwt_token(token, True)
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
    token_data = jwt_manager.validate_jwt_token(token, True)
    if token_data is None:
        return jsonify("Invalid token"), HTTPStatus.FORBIDDEN
    if not message_service.is_user_receiver_of_message(token_data['username'], message_id):
        return jsonify("Not allowed"), HTTPStatus.FORBIDDEN

    if not message_service.delete_message(message_id):
        return jsonify("Error"), HTTPStatus.INTERNAL_SERVER_ERROR

    return jsonify("Success"), HTTPStatus.NO_CONTENT

@app.route("/hello", methods=["GET"])
@limiter.limit("1 per second")
def hello():
    return jsonify("Hello!"), HTTPStatus.OK

if __name__ == '__main__':
    DbController.prepare_database()
    app.run(debug=True, port=5000, host='0.0.0.0')