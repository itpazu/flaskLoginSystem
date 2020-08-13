from flask import json, request, Response


def generate_response(msg):

    return Response(
        response=json.dumps(msg, default=str),
        status=200,
        mimetype="application/json")


def response_with_headers(msg):

    return Response(
        response=json.dumps(msg, default=str),
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                 'Access-Control-Allow-Credentials': "true",
                 'Access-Control-Allow-Headers': "Content-Type",
                 })


def response_with_token(msg):
    return Response(
        response=json.dumps(msg, default=str),
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                 'Access-Control-Allow-Credentials': "true",
                 'Access-Control-Allow-Headers': ["Content-Type", "Authorization"],
                 'Access-Control-Expose-Headers': ["Authorization"],
                 })


def build_cors_preflight_response():
    response = Response(
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000", 'Access-Control-Allow-Credentials': "true",
                 'Access-Control-Allow-Headers': ["Content-Type", "token"]}

    )
    return response
