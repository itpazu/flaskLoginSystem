from flask import request
from app.users_profile import bp
from app.db.Data_Layer_user_profile import DataLayerProfile
from app.decorators import Decorators
from app.make_response import ReturnResponse
from app.email import Email
import os
from flask_cors import CORS

dataLayer = DataLayerProfile()
decorators = Decorators()
response = ReturnResponse()
flask_email = Email()
UPLOAD_FOLDER = "uploads"
BUCKET = "keepershome-profile-photos"


@bp.route('/get_user_info', methods=['GET', 'POST', 'OPTIONS'])
@decorators.token_required
def get_user_info():
    if request.method == "OPTIONS":
        return response.build_cors_preflight_response()
    elif request.method == "POST":
        try:
            content = request.json
            _id = content['_id']
            selected_user = dataLayer.get_doc_by_user_id(_id)
            keys = ["_id", "role", "first_name", "last_name", "email", "photo"]
            new_dic = {key: selected_user[key] for key in keys}
            if new_dic["photo"] != '':
                new_photo = new_dic["photo"].decode()
                new_dic["photo"] = new_photo

            return response.response_with_headers(new_dic)

        except Exception as e:
            return response.error_response(str(e), 400)


@bp.route('/upload_file', methods=["GET", "POST", "OPTIONS"])
def upload_file():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()
    elif request.method == "POST":
        try:
            content = request.json
            _id = content["_id"]
            f = request.files['file']
            f.filename = f"{_id}.jpg"
            f.save(os.path.join(UPLOAD_FOLDER, f.filename))
            dataLayer.upload_file(_id, f"uploads/{f.filename}", BUCKET)

            return response.generate_response(string)

        except Exception as e:
            return response.error_response(str(e))


@bp.route('/delete_photo', methods=["DELETE"])
def delete_photo():
    try:
        content = request.json
        _id = content["_id"]
        file_name = f"{_id}.jpg"
        dataLayer.delete_photo(_id, file_name, BUCKET)
        return response.generate_response("The photo was deleted successfully!")
    except Exception as e:
        return response.error_response(str(e))


@bp.route('/edit_account_details', methods=["POST", "OPTIONS"])
@decorators.token_required
def edit_account_details():
    if request.method == "OPTIONS":
        return response.build_cors_preflight_response()
    elif request.method == "POST":
        try:
            content = request.json
            dataLayer.edit_account_details(content)
            return response.response_with_headers("The details have been edited successfully!")

        except Exception as error:
            return response.error_response("update failed:" + str(error))
