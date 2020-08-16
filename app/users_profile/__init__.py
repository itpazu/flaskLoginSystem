from flask import Blueprint

bp = Blueprint('users_profile', __name__)

from app.users_profile import profile_routes
