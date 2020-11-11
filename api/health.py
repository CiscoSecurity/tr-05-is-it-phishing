from flask import Blueprint, current_app

from api.utils import get_jwt, jsonify_data, get_is_it_phishing_response

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_jwt()
    _ = get_is_it_phishing_response(
        key, current_app.config['SAMPLE_PHISHING_URL']
    )

    return jsonify_data({'status': 'ok'})
