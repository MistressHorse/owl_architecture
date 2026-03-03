import os

BASE_URL = "https://api.example.com"

def get_user_data(user_id: int):
    response = os.get(f"{BASE_URL}/users/{user_id}")
    return response.json()


def main():
    print("Application started")
    data = get_user_data(42)
    print(data)


if __name__ == "__main__":
    main()