from shared import DTOs
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from server.DbController import get_db
from shared.utils import is_password_secure

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


    def register_user(self, reg_dto: DTOs.RegisterDTO):
        if not is_password_secure(reg_dto.password):
            return False

        reg_dto.password = self.phash.hash(reg_dto.password)

        db = get_db()

        try:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO app_users (username, password, email, public_key) VALUES (?, ?, ?, ?)",
                (reg_dto.username, reg_dto.password, reg_dto.email, reg_dto.public_key)
            )
            db.commit()
            return True
        except Exception as e:
            print("Database error:", e)
            return False
    
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
                return user['user_id']
            except VerifyMismatchError as e:
                print("Verifyerror:", e)
                return False
        
        except Exception as e:
            print("Database error:", e)
            return False
    
user_service = UserService()