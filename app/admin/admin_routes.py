from flask import request, current_app
from app.admin import bp
from app.login.login_routes import solicit_new_pass


dataLayer = bp.db
decorators = bp.decorators
email_helper = bp.email
response = bp.response

@bp.route('/all_users', methods=['GET'])
@decorators.admin_required
def all_users():
    try:
        users = dataLayer.all_users('Users')
        return response.generate_response(users)

    except Exception as error:
        return response.error_response(error, request.path)


@bp.route('/add_user', methods=["POST"])
@decorators.admin_required
def add_user():
    try:
        content = request.json
        added_user = dataLayer.add_user(content, current_app.config['ENV']) if current_app.config['TESTING'] else\
            dataLayer.add_user(content)
        email_address = added_user['email']
        user_id = added_user['_id']
        token = added_user['token']

        sent_mail = email_helper.send_password_by_mail(email_address, user_id, token)

        return response.response_with_headers(sent_mail)

    except Exception as error:
        return response.error_response(error, request.path)


@bp.route('/unblock_user', methods=["DELETE", "GET", "UPDATE"])
@decorators.admin_required
def unblock_user():
    try:
        email = request.json["email"]
        dataLayer.delete_email_attempts(email)
        dataLayer.delete_block_field(email)
        return solicit_new_pass()
    except Exception as error:
        return response.error_response('unblocking user failed: {}'.format(str(error)), request.path)


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





