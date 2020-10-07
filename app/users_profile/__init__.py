from app.bp_constructor import construct_bp
from app.db.Data_Layer_user_profile import DataLayerProfile

bp = construct_bp('users_profile', DataLayerProfile)


from app.users_profile import profile_routes
