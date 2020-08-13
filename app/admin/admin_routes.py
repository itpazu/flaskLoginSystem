from flask import json, request, Response
from app.admin import bp
from app.db.Data_Layer_auth import DataLayer_auth
from app.db.Data_Layer_admin import DataLayer_admin
from app.decorators import Decorators
from app.email import Email
from app.login.login_routes import solicit_new_pass

# dataLayer = DataLayer_auth()
dataLayer = DataLayer_admin()
decorators = Decorators()
flask_email = Email()

@bp.route('/all_users', methods=['GET', 'POST'])
@decorators.admin_required
def all_users():
    try:
        users = dataLayer.all_users()
        all_users_list = []

        for i in users:
            all_users_list.append(i)

        response = Response(response=(json.dumps({"users": all_users_list}, default=str)), status=200,
                                              mimetype="application/json")
        return response

    except Exception as e:
        return json.dumps(e, default=str), 400, {"Content-Type": "application/json"}


@bp.route('/add_user', methods=["POST"])
@decorators.admin_required
def add_user():
    try:
        content = request.json
        added_user = dataLayer.add_user(content)
        email_address = added_user['email']
        user_id = added_user['_id']
        token = added_user['token']
        sent_mail = flask_email.send_password_by_mail(email_address, user_id, token)

        return sent_mail

    except Exception as error:
        return json.dumps(error, default=str), 400, {"Content-Type": "application/json"}


@bp.route('/unblock_user', methods=["DELETE", "GET", "UPDATE"])
@decorators.admin_required
def unblock_user():
    try:
        email = request.json["email"]
        dataLayer.delete_email_attempts(email)
        dataLayer.delete_block_field(email)
        return solicit_new_pass()
    except Exception as error:
        return json.dumps('unblocking user failed: {}'.format(error), default=str), 401, {
            "Content-Type": "application/json"}


@bp.route('/delete_user', methods=["DELETE"])
@decorators.admin_required
def delete_user():
    try:
        content = request.json
        _id = content['user_id']  # must stay user_id!
        deleted_user = dataLayer.delete_user(_id)
        resp = json.dumps(deleted_user, default=str), 200, {"Content-Type": "application/json"}
        return resp
    except Exception as e:
        return json.dumps('Delete failed: {}'.format(e), default=str), 401, {"Content-Type": "application/json"}


@bp.route('/make_admin/<string:_id>', methods=["POST"])
def make_admin(_id):
    new_admin = dataLayer.make_admin(_id)
    resp = json.dumps(new_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@bp.route('/demote_admin/<string:_id>', methods=["POST"])
def demote_admin(_id):
    demoted_admin = dataLayer.demote_admin(_id)
    resp = json.dumps(demoted_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@bp.route('/change_email/<string:_id>', methods=["POST"])
def change_email(_id):
    changed_email = dataLayer.change_email(_id)
    resp = json.dumps(changed_email, default=str), 200, {"Content-Type": "application/json"}
    return resp
