from sqlalchemy import text


def find_user(name: str):
    return text("SELECT * FROM users WHERE name = :name").bindparams(name=name)
