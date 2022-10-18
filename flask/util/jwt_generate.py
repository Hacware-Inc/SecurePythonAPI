from datetime import datetime, timedelta

import jwt
import secrets


def generate_secret():
    key_len = 32
    secret = create_secret(key_len)
    print(secret)


def create_secret(key_len):
    secret = secrets.token_urlsafe(key_len)
    return secret


def generate_both_jwt():
    secret = secrets.token_urlsafe(32)
    print(secret)

    user_id_1 = secrets.token_urlsafe(16)
    role_1 = "user"
    jwt_user = create_jwt(user_id_1, role_1, secret)
    print(jwt_user)

    user_id_2 = secrets.token_urlsafe(16)
    role_2 = "admin"
    jwt_admin = create_jwt(user_id_2, role_2, secret)
    print(jwt_admin)


def create_jwt(uid, role, secret):
    # give the token an hour to live
    exp_date = datetime.utcnow() + timedelta(0, 3600)

    payload = {"user_id": uid, "role": role, "exp": exp_date}
    encoded_jwt = jwt.encode(payload, secret, algorithm="HS256")
    return encoded_jwt


def main():
    # generate_secret()
    generate_both_jwt()
    # create_jwt()


if __name__ == '__main__':
    main()
