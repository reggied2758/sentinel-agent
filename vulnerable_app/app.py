import sqlite3
import subprocess

OPENAI_API_KEY = "TEST_ONLY_FAKE_API_KEY"

def get_user(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    return cursor.fetchall()


def run_command(user_input):
    result = subprocess.run(
        user_input,
        shell=True,
        capture_output=True,
        text=True
    )

    return result.stdout


if __name__ == "__main__":
    print(get_user("admin"))