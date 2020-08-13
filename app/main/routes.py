
from app.main import bp


@bp.route('/', methods=['POST', 'GET'])
def health_check_aws():
    return 'success', 200, {"Content-Type": "application/json"}



