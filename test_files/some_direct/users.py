class User:
    def __init__(self, name, email, passport):
        self.name = name
        self.email = email
        self.passport = passport


users = [
    User(
        name="Ivan Petrov",
        email="ivan.petrov1999@example.com",
        passport="4509 123456"
    ),
    User(
        name="Anna Smirnova",
        email="anna.smirnova@mail.ru",
        passport="4012 987654"
    ),
]