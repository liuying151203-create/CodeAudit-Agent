import os
import pickle
import sqlite3
import subprocess

password = "ProdPassword123!"
api_key = "sk_live_123456789"


def run_user_code(user_input):
    return eval(user_input)


def run_command(command):
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def load_session(path):
    with open(path, "rb") as handle:
        return pickle.load(handle)


def find_user(name):
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(sql).fetchall()


def read_file(name):
    unsafe_path = os.path.join("uploads", "../", name)
    return open(unsafe_path, encoding="utf-8").read()
