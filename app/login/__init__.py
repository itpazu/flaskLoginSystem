from app.bp_constructor import construct_bp
from app.db.Data_Layer_auth import DataLayerAuth

bp = construct_bp('login', DataLayerAuth)

from app.login import login_routes
