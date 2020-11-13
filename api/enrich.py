from functools import partial
from datetime import datetime
from concurrent.futures.thread import ThreadPoolExecutor
from os import cpu_count

from flask import Blueprint, g

from api.schemas import ObservableSchema
from api.utils import (
    get_json, get_jwt, jsonify_data, current_app,
    jsonify_result, append_warning
)
from api.client import IsItPhishingClient
from api.errors import IsItPhishingTimeout, IsItPhishingNotExplored

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


def time_to_ctr_format(time):
    return time.isoformat() + 'Z'


def get_valid_time():
    start_time = datetime.utcnow()
    end_time = start_time + current_app.config['ENTITY_RELEVANCE_PERIOD']
    return {
        'start_time': time_to_ctr_format(start_time),
        'end_time': time_to_ctr_format(end_time),
    }


def extract_verdict(output, observable):
    status = output['status']
    doc = {
        'observable': observable,
        'disposition':
            current_app.config['STATUS_MAPPING'][status]['disposition'],
        'disposition_name':
            current_app.config['STATUS_MAPPING'][status]['disposition_name'],
        'valid_time': get_valid_time(),
        'type': 'verdict'
    }

    return doc


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    def deliberate(observable):
        response = client.get_is_it_phishing_response(observable['value'])
        return response, observable

    api_key = get_jwt()
    client = IsItPhishingClient(
        api_key,
        current_app.config['USER_AGENT'],
        current_app.config['API_URL'],
        current_app.config['REQUEST_JSON']
    )

    observables = get_observables()
    g.verdicts = []
    observables = [
        obs for obs in observables if obs['type'] == 'url'
    ]

    if observables:
        with ThreadPoolExecutor(
                max_workers=min(len(observables), (cpu_count() or 1) * 5)
        ) as executor:
            iterator = executor.map(deliberate, observables)

        for output, obs in iterator:
            if output:
                warnings_mapping = {
                    'TIMEOUT': IsItPhishingTimeout(obs['value']),
                    'NOT_EXPLORED': IsItPhishingNotExplored(obs['value'])
                }

                g.verdicts.append(extract_verdict(output, obs))
                if output['status'] in warnings_mapping.keys():
                    append_warning(warnings_mapping[output['status']])

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    api_key = get_jwt()
    client = IsItPhishingClient(
        api_key,
        current_app.config['USER_AGENT'],
        current_app.config['API_URL'],
        current_app.config['REQUEST_JSON']
    )

    observables = get_observables()
    g.verdicts = []

    for observable in observables:
        value = observable['value']
        type_ = observable['type'].lower()
        if type_ == 'url':
            output = client.get_is_it_phishing_response(value)
            if output:
                g.verdicts.append(extract_verdict(output, observable))

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
