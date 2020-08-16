from flask import request
from app.admin import bp
from app.db.Data_Layer_admin import DataLayerAdmin
from app.decorators import Decorators
from app.email import Email
from app.login.login_routes import solicit_new_pass
from app.make_response import ReturnResponse

dataLayer = DataLayerAdmin()
decorators = Decorators()
email_helper = Email()
response = ReturnResponse()

@bp.route('/all_users', methods=['GET', 'POST'])
@decorators.admin_required
def all_users():
    try:
        users = dataLayer.all_users()
        return response.generate_response({"users": users})

    except Exception as error:
        return response.error_response(str(error))



@bp.route('/add_user', methods=["POST"])
@decorators.admin_required
def add_user():
    try:
        content = request.json
        added_user = dataLayer.add_user(content)
        email_address = added_user['email']
        user_id = added_user['_id']
        token = added_user['token']
        sent_mail = email_helper.send_password_by_mail(email_address, user_id, token)

        return response.response_with_headers(sent_mail)

    except Exception as error:
        return response.error_response(str(error))


@bp.route('/unblock_user', methods=["DELETE", "GET", "UPDATE"])
@decorators.admin_required
def unblock_user():
    try:
        email = request.json["email"]
        dataLayer.delete_email_attempts(email)
        dataLayer.delete_block_field(email)
        return solicit_new_pass()
    except Exception as error:
        return response.error_response('unblocking user failed: {}'.format(str(error)))


@bp.route('/delete_user', methods=["DELETE"])
@decorators.admin_required
def delete_user():
    try:
        content = request.json
        _id = content['user_id']
        deleted_user = dataLayer.delete_user(_id)
        return response.generate_response(deleted_user)
    except Exception as e:
        return response.error_response('Delete failed: {}'.format(str(e)))


@bp.route('/make_admin/<string:_id>', methods=["POST"])
def make_admin(_id):
    try:
        new_admin = dataLayer.make_admin(_id)
        return response.generate_response(new_admin)
    except Exception as e:
        return response.error_response((str(e)))


@bp.route('/demote_admin/<string:_id>', methods=["POST"])
def demote_admin(_id):
    try:
        demoted_admin = dataLayer.demote_admin(_id)
        return response.generate_response(demoted_admin)

    except Exception as e:
        return response.error_response((str(e)))

@bp.route('/change_email/<string:_id>', methods=["POST"])
def change_email(_id):
    try:
        changed_email = dataLayer.change_email(_id)
        return response.generate_response(changed_email)
    except Exception as e:
        return response.error_response((str(e)))
