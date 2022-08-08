""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health, MACRO_LIST
from connectors.cyops_utilities.builtins import make_cyops_request
    
logger = get_logger("qianxin-threat-intel")

class QianxinConnector(Connector):
  def execute(self, config, operation, params, **kwargs):
    try:
      config['connector_info'] = {"connector_name": self._info_json.get('name'),
        "connector_version": self._info_json.get('version')}
      operation = operations.get(operation)
      if not operation:
        logger.error('Unsupported operation: {}'.format(operation))
        raise ConnectorError('Unsupported operation')
      return operation(config, params)
    except Exception as err:
      logger.exception(err)
      raise ConnectorError(err)
  
  def check_health(self, config):
    config['connector_info'] = {"connector_name": self._info_json.get('name'),
      "connector_version": self._info_json.get('version')}
    return _check_health(config)

    def del_micro(self, config):
        for macro in MACRO_LIST:
            try:
                resp = make_cyops_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                if resp['hydra:member']:
                    macro_id = resp['hydra:member'][0]['id']
                    resp = make_cyops_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
            except Exception as e:
                logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)
