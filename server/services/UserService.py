import DTOs
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from DbController import get_db

class UserService():
    def __init__(self):
        self.phash = PasswordHasher()

    def user_exists(self, login: str) -> bool:
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("SELECT user_id FROM app_users WHERE login = ?;", (login,))
            return cursor.fetchone() is not None
        except Exception as e:
            print("Database error:", e)


    def register_user(self, reg_dto: DTOs.RegisterDTO):
        if not self.is_password_secure(reg_dto.password):
            return False

        reg_dto.password = self.phash.hash(reg_dto.password)

        db = get_db()

        try:
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO app_users (login, password, email, public_key) VALUES (?, ?, ?, ?)",
                (reg_dto.login, reg_dto.password, reg_dto.email, reg_dto.public_key)
            )
            db.commit()
            return True
        except Exception as e:
            print("Database error:", e)
            return False

    def is_password_secure(self, password: str) -> bool:
        if len(password) < 16:
            return False

        hasLower = False
        hasUpper = False
        hasDigit = False
        hasSpecialCharacter = False
        for c in password:
            if c.islower(): hasLower = True
            if c.isupper(): hasUpper = True
            if c.isdigit(): hasDigit = True
            if not c.isalnum(): hasSpecialCharacter = True
        
        return hasLower and hasUpper and hasDigit and hasSpecialCharacter
    
    def verify_login(self, login_dto: DTOs.LoginDTO) -> bool | int:
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("SELECT user_id, password FROM app_users WHERE login = ?;", (login_dto.login,))
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