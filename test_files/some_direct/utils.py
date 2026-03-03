import random
import string

def generate_id(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))


def log(message: str):
    print(f"[LOG] {message}")