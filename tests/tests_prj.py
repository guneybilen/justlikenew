from django.test import TestCase
from users.models import CustomUser as User
import json

test_user = {"email": "test1@test.com", "nickname": "nick1", "password": "testpassword1"}


class TestPRJ(TestCase):
    def setUp(self):
        new_user = User.objects.create(email=test_user["email"], nickname=test_user["nickname"])
        new_user.set_password(test_user["password"])
        new_user.save()

    def test_get_token(self):
        res = self.client.post('/api/token/',
                               data=json.dumps({
                                   'email': test_user["email"],
                                   'nickname': test_user["nickname"],
                                   'password': test_user["password"],
                               }),
                               content_type='application/json',
                               )
        result = json.loads(res.content)
        self.assertTrue("access" in result)
        return result["access"]

    def test_add_items_forbidden(self):
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "m3",
                                   "model": "550",
                                   "entry": "best hard drive...",
                                   "price": 100,
                                   "seller": 1
                               }),
                               content_type='application/json',
                               )
        self.assertEquals(res.status_code, 401)
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "toshiba",
                                   "model": "550",
                                   "entry": "better hard drive...",
                                   "price": 125,
                                   "seller": 1
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'Bearer WRONG TOKEN'
                               )
        self.assertEquals(res.status_code, 401)
