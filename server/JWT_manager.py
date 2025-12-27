import base64
from Crypto.Hash import HMAC, SHA256
import time
from dotenv import load_dotenv
import os
import json
import hmac

class JWT_manager():
    def __init__(self):
        self.header64 = self.safe_base64_encode({
            "alg": "HS256",
            "typ": "JWT"
        })

        load_dotenv()
        self.secret = os.getenv('JWT_SECRET')
        if self.secret is None:
            raise RuntimeError("Could not get JWT secret from .env !")

    def safe_base64_encode(self, data):
        json_str = json.dumps(data, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode("utf-8")).rstrip(b"=")

    def safe_base64_decode(self, data):
        padding = '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    def make_payload64(self, uid, login):
        time_now = int(time.time())
        time_valid_seconds = 3600
        payload = {
            "sub": uid,
            "iat": time_now,
            "exp": time_now + time_valid_seconds,
            "username": login,
            "iss": "sss.serv"
        }
        return self.safe_base64_encode(payload)

    def make_signature(self, payload64):
        h = HMAC.new(self.secret.encode("utf-8"), digestmod=SHA256)
        to_sign = self.header64 + b'.' + payload64
        h.update(to_sign)
        signature64 = base64.urlsafe_b64encode(h.digest()).rstrip(b"=")

        return signature64
    
    def create_token(self, uid, login):
        payload64 = self.make_payload64(uid, login)
        signature = self.make_signature(payload64).decode("utf-8") # now it's a text to make it sendable in JSON
        return self.header64.decode("utf-8") + '.' + payload64.decode("utf-8") + '.' + signature

    def validate_jwt_token(self, token: str) -> None | dict :
        try:
            header, payload, signature = token.split('.')
        except Exception as e:
            print("Invalid token structure:", e)
            return None

        intended_signature = self.make_signature(payload.encode("utf-8")).decode("utf-8")
        if not hmac.compare_digest(signature, intended_signature):
            print("Invalid signature")
            return None

        if header.encode("utf-8") != self.header64:
            print("Incorrect header")
            return None

        try:
            payload_dict = json.loads(self.safe_base64_decode(payload).decode("utf-8"))

            if int(time.time()) > payload_dict.get("exp", 0):
                print("Expired token")
                return None

            return {'username': payload_dict['username'], 'uid': payload_dict['sub']}
        except (json.JSONDecodeError, TypeError, AttributeError) as e:
            print("Invalid payload data:", e)
            return None