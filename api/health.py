from flask import Blueprint, current_app

from api.utils import get_jwt, jsonify_data
from api.client import IsItPhishingClient

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    api_key = get_jwt()
    client = IsItPhishingClient(
        api_key,
        current_app.config['USER_AGENT'],
        current_app.config['API_URL'],
        current_app.config['REQUEST_JSON']
    )

    _ = client.get_is_it_phishing_response(
        current_app.config['SAMPLE_PHISHING_URL']
    )

    return jsonify_data({'status': 'ok'})
