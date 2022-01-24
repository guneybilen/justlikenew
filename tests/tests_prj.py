from django.test import TestCase
from users.models import CustomUser as User
import json

test_user = {"email": "test1@test.com", "nickname": "nick1", "password": "testpassword1"}


class TestPRJ(TestCase):
    def setUp(self):
        new_user = User.objects.create(email=test_user["email"], nickname=test_user["nickname"])
        new_user.set_password(test_user["password"])
        new_user.save()
        self.id = new_user.id

    def get_token(self):
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
                               HTTP_AUTHORIZATION=f'JWT WRONG TOKEN'
                               )
        self.assertEquals(res.status_code, 401)

    def test_add_items_ok(self):
        token = self.get_token()
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "toshiba",
                                   "model": "550",
                                   "entry": "better hard drive...",
                                   "price": 125.00,
                                   "seller": 1
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 201)

        brand = json.loads(res.content)["brand"]
        model = json.loads(res.content)["model"]
        entry = json.loads(res.content)["entry"]
        price = json.loads(res.content)["price"]
        self.assertEquals(brand, 'toshiba')
        self.assertEquals(model, '550')
        self.assertEquals(entry, 'better hard drive...')
        self.assertEquals(float(price), 125)

    def test_add_items_wrong_data(self):
        token = self.get_token()
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "date": "2020-01-01",
                                   "item": "Hard Drive",
                                   "price": -1,
                                   "quantity": 10,
                                   "seller": 1
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 400)

        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "date": "2020-01-01",
                                   "item": "Hard Drive",
                                   "price": 1,
                                   "quantity": -10,
                                   "seller": 1
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 400)

        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "date": "2020-01-01",
                                   "item": "",
                                   "price": 1,
                                   "quantity": 10,
                                   "seller": 1
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 400)

    def test_add_orders_calculate(self):
        token = self.get_token()
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "toshiba",
                                   "model": "550",
                                   "entry": "better hard drive...",
                                   "price": 125.00,
                                   "seller": 1,
                                   "amount": 10000  # should be ignored
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 201)
        result = json.loads(res.content)["price"]
        self.assertEquals(float(result), 125.00)

    def test_get_records(self):
        token = self.get_token()
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "toshiba",
                                   "model": "550",
                                   "entry": "better hard drive...",
                                   "price": 125.00,
                                   "seller": 1,
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 201)
        brand1 = json.loads(res.content)["brand"]

        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "toshiba",
                                   "model": "750",
                                   "entry": "better hard drive...",
                                   "price": 125.00,
                                   "seller": 1,
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 201)
        brand2 = json.loads(res.content)["brand"]

        res = self.client.get('/api/items/',
                              content_type='application/json',
                              HTTP_AUTHORIZATION=f'JWT {token}'
                              )

        self.assertEquals(res.status_code, 200)
        results = json.loads(res.content)
        result1 = json.loads(res.content)[0]["brand"]
        result2 = json.loads(res.content)[1]["brand"]
        self.assertEquals(len(results), 2)  # 2 records
        self.assertTrue(result1 == brand1 or result2 == brand2)
        self.assertTrue(result1 == brand2 or result1 == brand2)

        slug1 = json.loads(res.content)[0]["slug"]
        res = self.client.get(f'/api/items/{slug1}/',
                              content_type='application/json',
                              HTTP_AUTHORIZATION=f'JWT {token}'
                              )
        self.assertEquals(res.status_code, 200)
        result = json.loads(res.content)
        self.assertEquals(result[0]["brand"], "toshiba")
        self.assertEquals(result[0]["model"], "750")
        self.assertEquals(result[0]["entry"], "better hard drive...")

    def test_put_delete_items(self):
        token = self.get_token()
        res = self.client.post('/api/items/',
                               data=json.dumps({
                                   "brand": "toshiba",
                                   "model": "550",
                                   "entry": "better hard drive...",
                                   "price": 125.00,
                                   "seller": 1,
                               }),
                               content_type='application/json',
                               HTTP_AUTHORIZATION=f'JWT {token}'
                               )
        self.assertEquals(res.status_code, 201)
        slug = json.loads(res.content)["slug"]
        res = self.client.put(f"/api/items/{slug}/",
                              data=json.dumps({
                                  "brand": "m5",
                                  "model": "m9",
                                  "entry": "better hard drive...",
                                  "price": 125.00,
                                  "seller": 1
                              }),
                              content_type='application/json',
                              HTTP_AUTHORIZATION=f'JWT {token}'
                              )

        self.assertEquals(res.status_code, 200)
        price = json.loads(res.content)["price"]
        slug = json.loads(res.content)["slug"]
        self.assertEquals(float(price), 125.00)
        res = self.client.get(f'/api/items/{slug}/',
                              content_type='application/json',
                              HTTP_AUTHORIZATION=f'JWT {token}'
                              )
        self.assertEquals(res.status_code, 200)
        brand = json.loads(res.content)[0]["brand"]
        model = json.loads(res.content)[0]["model"]
        price = json.loads(res.content)[0]["price"]
        entry = json.loads(res.content)[0]["entry"]
        self.assertEquals(brand, 'm5')
        self.assertEquals(model, 'm9')
        self.assertEquals(float(price), 125.00)
        self.assertEquals(entry, "better hard drive...")

        res = self.client.delete(f'/api/items/{slug}/',
                                 content_type='application/json',
                                 HTTP_AUTHORIZATION=f'JWT {token}'
                                 )
        self.assertEquals(res.status_code, 204)  # Gone

        res = self.client.get(f'/api/items/{slug}/',
                              content_type='application/json',
                              HTTP_AUTHORIZATION=f'JWT {token}'
                              )
        self.assertEquals(res.status_code, 404)  # Not found
