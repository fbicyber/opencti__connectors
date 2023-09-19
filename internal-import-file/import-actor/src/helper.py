import os

import yaml
from pycti import OpenCTIConnectorHelper


def get_config():
    # Instantiate the connector helper from config
    base_path = os.path.dirname(os.path.abspath(__file__))
    config_file_path = base_path + "/config/config.yml"
    config = (
        yaml.load(open(config_file_path), Loader=yaml.FullLoader)
        if os.path.isfile(config_file_path)
        else {}
    )
    return config


def get_helper(config):
    return OpenCTIConnectorHelper(config)
