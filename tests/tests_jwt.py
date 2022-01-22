from django.test import TestCase
from users.models import CustomUser as User
import json

test_users = [
    {"email": "test1@test.com", "nickname": "nick1", "password": "testpassword1"},
    {"email": "test2@test.com", "nickname": "nick2", "password": "testpassword2"},
]


class LoginTest(TestCase):
    def setUp(self):
        for user in test_users:
            new_user = User.objects.create(email=user["email"], nickname=user["nickname"])
            new_user.set_password(user["password"])
            new_user.save()

    def test_login(self):
        USER1 = test_users[0]
        res = self.client.post('/api/token/',
                               data=json.dumps({
                                   'email': USER1["email"],
                                   'nickname': USER1["nickname"],
                                   'password': USER1["password"],
                               }),
                               content_type='application/json',
                               )
        result = json.loads(res.content)
        self.assertTrue("access" in result)
