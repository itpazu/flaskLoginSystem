import unittest
import json
from app import create_app
from config_tests import ConfigTests
from app.db.Data_Layer import DataLayer


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app(ConfigTests)
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.db = DataLayer().get_db()
        self.tester = self.app.test_client()
        self.token = ''
        self.csrf = ''
        self.fresh_token = ''



    def test_a_sign_up(self):
        # print('in sign up')
        # Given
        payload = json.dumps({
            "last_name": "bisli",
            "first_name": "dala",
            "email": "kocefaw248@acceptmail.net",
            "role": "user",
        })
        # when
        response = self.tester.post('/add_user', headers={"content-Type": "application/json"}, data=payload)

        # then
        self.assertEqual(int, type(int(response.json['user_id'])))
        self.assertEqual('200 OK', response.status)

    def test_b_login(self):
        # print('login')
        sign_payload = json.dumps({
            "last_name": "bisli",
            "first_name": "dala",
            "email": "kocefaw248@acceptmail.net",
            "role": "user",
        })
        # when
        sign_up_resp = self.tester.post('/add_user', headers={"content-Type": "application/json"}, data=sign_payload)

        payload = json.dumps({"email": "kocefaw248@acceptmail.net", "password": "12345678"})
        response = self.tester.post('/login', headers={"content-Type": "application/json"}, data=payload)

        print(response.json)
        print(response.headers)
        self.assertEqual('200 OK', response.status)

    def tearDown(self):
        # print('in teardown')
        for collection in self.db.list_collection_names():
            self.db.drop_collection(collection)


if __name__ == '__main__':
    unittest.main()
