from flask import json, request, Response
from app.users_profile import bp
from app.db.Data_Layer_user_profile import DataLayerProfile
from app.decorators import Decorators
from app.email import Email
import base64

dataLayer = DataLayerProfile()
decorators = Decorators()
flask_email = Email()

@bp.route('/get_user_info', methods=['GET', 'POST'])
def get_user_info():
    try:
        content = request.json
        _id = content['_id']
        selected_user = dataLayer.get_doc_by_user_id(_id)
        keys = ["_id", "role", "first_name", "last_name", "email", "photo"]
        new_dic = {key: selected_user[key] for key in keys}
        if new_dic["photo"] != '':
            new_photo = new_dic["photo"].decode()
            new_dic["photo"] = new_photo
        response = Response (
            response=json.dumps(new_dic),
            status=200,
            mimetype="application/json"
        )
        return response
    except Exception as e:
        return json.dumps(e, default=str), 400, {"Content-Type": "application/json"}


@bp.route('/add_photo', methods=["POST"])
def add_photo():
    try:
        content = request.json
        _id = content["_id"]
        photo = content["photo"]
        with open(str(photo), "rb") as imageFile:
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


@bp.route('/edit_account_details', methods=["POST"])
def edit_account_details():
    try:
        content = request.json
        dataLayer.edit_account_details(content)
        response = Response(response=json.dumps("The details have been edited successfully!"),
                                              status=200,
                                              mimetype='application/json',
                                              headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                                                       'Access-Control-Allow-Credentials': "true",
                                                       'Access-Control-Allow-Headers': ["Content-Type"]}
                                              )
        return response
    except Exception as error:
        response = Response(response=json.dumps("update failed:" + str(error)),
                                              status=401,
                                              mimetype='application/json')
        return response