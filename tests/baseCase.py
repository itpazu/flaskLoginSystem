import unittest
import json
from app import create_app
from config_tests import ConfigTests
from app.decorators import Decorators
from functools import wraps
from app.db.Data_Layer import DataLayer




def mock_decorator(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function

# circumvent the decorators
Decorators.admin_required = staticmethod(mock_decorator)
Decorators.token_required = staticmethod(mock_decorator)


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app(ConfigTests)
        self.db = DataLayer().get_db()
        self.tester = self.app.test_client()


    def test_a_sign_up(self):

        payload = json.dumps({
            "last_name": "bisli",
            "first_name": "dala",
            "email": "kocefaw248@acceptmail.net",
            "role": "user",
        })
        response = self.tester.post('/add_user', headers={"content-Type": "application/json"}, data=payload)

        self.assertEqual(int, type(int(response.json['user_id'])))
        self.assertEqual('200 OK', response.status)

    def test_b_login(self):
        sign_payload = json.dumps({
            "last_name": "bisli",
            "first_name": "dala",
            "email": "kocefaw248@acceptmail.net",
            "role": "user",
        })
        res = self.tester.post('/add_user', headers={"content-Type": "application/json"}, data=sign_payload)
        generated_id = res.json['user_id']
        payload = json.dumps({"email": "kocefaw248@acceptmail.net", "password": "12345678"})
        response = self.tester.post('/login', headers={"content-Type": "application/json"}, data=payload)
        login_id = response.json['_id']
        self.assertEqual('200 OK', response.status)
        self.assertEqual(generated_id, login_id)



    def tearDown(self):
        for collection in self.db.list_collection_names():
            self.db.drop_collection(collection)


if __name__ == '__main__':
    unittest.main()
