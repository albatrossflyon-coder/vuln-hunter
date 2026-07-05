import os
import subprocess

def run_command_safe(user_input: str) -> str:
    result = subprocess.run(["echo", user_input], capture_output=True, text=True, shell=False)
    return result.stdout

def get_user_safe(db, username: str):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

API_KEY = os.environ.get("API_KEY")
