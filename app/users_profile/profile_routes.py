from flask import json, request, Response
from app.users_profile import bp
from app.db.Data_Layer_user_profile import DataLayerProfile
from app.decorators import Decorators
from app.email import Email
import base64
from app.make_response import build_cors_preflight_response, response_with_headers

dataLayer = DataLayerProfile()
decorators = Decorators()
flask_email = Email()

@bp.route('/get_user_info', methods=['GET', 'POST', 'OPTIONS'])
def get_user_info():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()
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

            return response_with_headers(new_dic)

        except Exception as e:
            return json.dumps(e, default=str), 400, {"Content-Type": "application/json"}


@bp.route('/add_photo', methods=["POST"])
def add_photo():
    try:
        content = request.json
        _id = content["_id"]
        file = request.files['file']
        with open(file, "rb") as imageFile:
            string = base64.b64decode(imageFile.read())
        dataLayer.add_photo(_id, string)

        response = Response(
            response=json.dumps(string),
            status=200,
            mimetype="application/json"
        )
        return response
    except Exception as e:
        return json.dumps(e, default=str), 400, {"Content-Type": "application/json"}


@bp.route('/delete_photo', methods=["DELETE"])
def delete_photo():
    try:
        content = request.json
        _id = content["_id"]
        dataLayer.delete_photo(_id)
        response = Response(
            response=json.dumps("The photo was deleted successfully!"),
            status=200,
            mimetype="application/json"
        )
        return response
    except Exception as e:
        return json.dumps(e, default=str), 400, {"Content-Type": "application/json"}


@bp.route('/edit_account_details', methods=["POST", "OPTIONS"])
def edit_account_details():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()
    elif request.method == "POST":
        try:
            content = request.json
            dataLayer.edit_account_details(content)
            return response_with_headers("The details have been edited successfully!")

        except Exception as error:
            response = Response(response=json.dumps("update failed:" + str(error)),
                                                  status=401,
                                                  mimetype='application/json')
            return response