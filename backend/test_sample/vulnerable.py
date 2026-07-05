import os
import subprocess
import sqlite3

def run_command(user_input):
    os.system("echo " + user_input)

def get_user(db, username):
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def unsafe_eval(user_code):
    return eval(user_code)

API_KEY = "sk-ant-abc123hardcodedsecretkey"
