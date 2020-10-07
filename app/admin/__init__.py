from app.bp_constructor import construct_bp
from app.db.Data_Layer_admin import DataLayerAdmin

bp = construct_bp('admin', DataLayerAdmin)

from app.admin import admin_routes
