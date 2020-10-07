from flask import render_template
from flask_mail import Message
from app import mail


class Email():

    @staticmethod
    def notify_admins(email, recipients):
        try:
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
            url = 'http://keepershomeclient.s3-website.eu-central-1.amazonaws.com/change_pass/path?id=' + user_id + '&token=' + token

            msg = Message('Reset Password', recipients=[email_address])
            msg.body = render_template('reset_password.txt', url=url)
            msg.html = render_template('reset_pass.html',
                                       url=url)
            mail.send(msg)
        except Exception as error:
            raise Exception({"message": "request failed turn to your admin",
                             "log": " password reset for user %s failed. Email could not be sent. reason: %s"
                                    % (email_address, (str(error))), "status_code": 401})

        return {"message": "email to the new user has been sent successfully",
                "user_id": user_id}
