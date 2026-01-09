from http import HTTPStatus

from shared import DTOs
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from server.DbController import get_db
import shared.utils as utils
from shared.TOTP_manager import totp_manager
import re

class UserService:
    def __init__(self):
        self.phash = PasswordHasher()

    def user_exists(self, username: str) -> bool:
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("SELECT user_id FROM app_users WHERE username = ?;", (username,))
            return cursor.fetchone() is not None
        except Exception as e:
            print("Database error:", e)
            return False

    def is_email_in_use(self, email: str) -> bool:
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "SELECT email FROM app_users WHERE email = ?;",
                (email,)
            )
            result = cursor.fetchone()
            return result is not None

        except Exception as e:
            print("Database error:", e)
            return True

    def is_email_valid(self, email: str):
        if 3 <= len(email) <= 255:
            regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$]'
            if re.match(regex, email):
                return True
        return False

    def register_user(self, reg_dto: DTOs.RegisterDTO):
        if not (utils.is_password_secure(reg_dto.password) and utils.verify_username(reg_dto.username)
                and self.is_email_valid(reg_dto.email)):
            return HTTPStatus.BAD_REQUEST
        if self.is_email_in_use(reg_dto.email) or user_service.user_exists(reg_dto.username):
            return HTTPStatus.CONFLICT

        reg_dto.password = self.phash.hash(reg_dto.password)
        secret = totp_manager.generate_secret()
        encrypted_secret = totp_manager.encrypt_secret(secret)

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO app_users (username, password, email, public_key, secret) VALUES (?, ?, ?, ?, ?)",
                (reg_dto.username, reg_dto.password, reg_dto.email, reg_dto.public_key, encrypted_secret)
            )
            return secret
        except Exception as e:
            print("Database error:", e)
            return HTTPStatus.INTERNAL_SERVER_ERROR
    
    def verify_login(self, login_dto: DTOs.LoginDTO) -> bool | int:
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("SELECT user_id, password FROM app_users WHERE username = ?;", (login_dto.username,))
            user = cursor.fetchone()
            
            if user is None:
                return False
            
            try:
                self.phash.verify(user['password'], login_dto.password)
            except VerifyMismatchError as e:
                print("Verify error:", e)
                return False

            return user['user_id']

        except Exception as e:
            print("Database error:", e)
            return False

    def get_secret(self, user_id: int):
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("SELECT secret FROM app_users WHERE user_id = ?;", (user_id,))
            user = cursor.fetchone()

            if user is None:
                return None

            return totp_manager.decrypt_secret(user['secret'])

        except ValueError as e:
            print("Decryption error, likely MASTER_KEY mismatch:", e)
            return None
        except Exception as e:
            print("Database error:", e)
            return None
    
user_service = UserService()