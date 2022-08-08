""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
import requests
import json

logger = get_logger('qianxin-threat-intel')


def validate_response(response):
    try:
        response_json = response.json()
    except Exception:
        msg_string = "Unable to parse reply as a JSON : {text} with reason: {reason}".format(text=response.text,
                                                                                             reason=response.reason)
        raise ConnectorError(msg_string)
    if response.ok:
        status_code = response_json.get('status', '')
        if status_code in [10000, 10100]:
            return response_json
    raise ConnectorError('{error}'.format(error=response_json))


def _get_config(config):
    server_url = config.get('server_url').strip('/')
    if server_url[:7] != 'http://' and server_url[:8] != 'https://':
        server_url = 'https://{}'.format(str(server_url))
    api_key = config.get('api_key')
    verify_ssl = config.get('verify_ssl')
    return server_url, api_key, verify_ssl


def _api_request(url, parameters=None, method='GET', data=None, headers=None, verify_ssl=False):
    logger.debug('url: {}'.format(url))
    logger.debug('data: {}'.format(data))
    logger.debug('parameters: {}'.format(parameters))
    try:
        api_response = requests.request(method=method, url=url, data=data, params=parameters, verify=verify_ssl,
                                        headers=headers)
        return validate_response(api_response)
    except Exception as e:
        raise ConnectorError(str(e))


def file_reputation(config, params):
    advance = params.get('advance', False)
    endpoint_map = {
        False: '/api/v2/malfile',
        True: '/api/v2/malfile_pro'
    }
    data = None
    parameters = {}
    headers = None
    method = 'GET'
    reputation_of = params.get('reputation_of')
    endpoint = endpoint_map.get(advance)
    server_url, api_key, verify_ssl = _get_config(config)
    if reputation_of == 'Batch':
        method = 'POST'
        headers = {'Content-Type': 'application/json'}
        hashes = params.get('hashes')
        data = {
            'apikey': api_key,
            'param': hashes
        }
        data = json.dumps(data)
    else:
        hash = params.get('hash')
        parameters = {
            'apikey': api_key,
            'param': hash
        }
    url = server_url + endpoint
    response = _api_request(url, method=method, parameters=parameters, data=data, headers=headers,
                            verify_ssl=verify_ssl)
    return response


def ip_reputation(config, params):
    endpoint_map = {
        'Single': '/ip/v2.1/reputation?ip={ip}'.format(ip=params.get('ip')),
        'Batch': '/ip/v2.1/reputations'
    }
    data = None
    reputation_of = params.get('reputation_of')
    endpoint = endpoint_map.get(reputation_of)
    server_url, api_key, verify_ssl = _get_config(config)
    headers = {'Api-Key': api_key}
    method = 'GET'
    if reputation_of == 'Batch':
        method = 'POST'
        headers.update({'Content-Type': 'application/json'})
        ips = params.get('ips')
        if isinstance(ips, str):
            ips = list(map(lambda x: x.strip(' '), ips.split(",")))
        data = json.dumps(ips)
    url_split = server_url.split('//')
    url_split.insert(1, '//webapi.')
    server_url = ''.join(url_split)
    url = server_url + endpoint
    response = _api_request(url, method=method, data=data, headers=headers, verify_ssl=verify_ssl)
    return response


def build_payload(params, make_list=[]):
    query_param = {}
    for k, v in params.items():
        if v is not None and v != '':
            query_param.update({k.strip('_value') if '_value' in k else k: list(
                map(lambda x: x.strip(' '), v.split(","))) if (isinstance(v, str) and ',' in v) or (not isinstance(v, list)
                                                                                                    and k in make_list) else v})
    return query_param


def get_loss_detection_data(config, params):
    endpoint_map = {
        'Single': '/api/v2/compromise',
        'Batch': '/api/v2/compromises',
    }
    request_of = params.get('request_of')
    params.pop('request_of')
    payload = build_payload(params, make_list=['params_value'])
    endpoint = endpoint_map.get(request_of)
    server_url, api_key, verify_ssl = _get_config(config)
    payload.update({'apikey': api_key})
    method = 'POST'
    headers = {'Content-Type': 'application/json'}
    data = json.dumps(payload)
    url = server_url + endpoint
    response = _api_request(url, method=method, data=data, headers=headers, verify_ssl=verify_ssl)
    return response


def _check_health(config):
    params = {'reputation_of': 'Single', 'ip': '8.8.8.8'}
    response = ip_reputation(config, params)
    if response:
        return True


operations = {
    "ip_reputation": ip_reputation,
    "file_reputation": file_reputation,
    "get_loss_detection_data": get_loss_detection_data
}
