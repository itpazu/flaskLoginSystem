from flask import current_app
from flask import json, render_template
from flask_mail import Message
from app.db.Data_Layer import DataLayer
from app import mail

dataLayer = DataLayer()

class Email():

    @staticmethod
    def notify_admins(email):
        try:
            admin_emails = list(dataLayer.get_admins())
            recipients = [admin.get("email") for admin in admin_emails]
            msg = Message('Suspicious login attempts to account {}'.format(email), recipients=recipients)
            msg.body = render_template('notify_admin.txt', email_address=email)
            msg.html = render_template('notify_admin.html',
                                       email_address=email)
            mail.send(msg)
            return 'email to admins has been successfully sent'
        except Exception as error:
            raise Exception('failed to send email: {}'.format(str(error)))

    @staticmethod
    def send_password_by_mail(email_address, user_id, token):
        try:
            url = 'http://localhost:3000/change_pass/path?id=' + user_id + '&token=' + token

            msg = Message('Reset Password', recipients=[email_address])
            msg.body = render_template('reset_password.txt', url=url)
            msg.html = render_template('reset_pass.html',
                                       url=url)
            mail.send(msg)
        except Exception as error:
            raise ValueError("failed to send email {}".format(str(error)))

        resp = current_app.response_class(
            response=json.dumps({"message": "email to the new user has been sent successfully",
                                 "user_id": user_id}),
            status=200,
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                     'Access-Control-Allow-Credentials': "true",
                     'Access-Control-Allow-Headers': "Content-Type",
                     }
        )
        return resp