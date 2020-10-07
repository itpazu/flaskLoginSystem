from app.bp_constructor import construct_bp
from ..db.Data_Layer_student import DataLayerStudent


bp = construct_bp('main', DataLayerStudent)

from app.main import routes

