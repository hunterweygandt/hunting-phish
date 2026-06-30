#reads API keys from config.ini
import configparser
import os

# config.ini sits in the project root, one level up from this parsers/ folder
_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config.ini"
)

_parser = configparser.ConfigParser()
# .read() quietly does nothing if the file is missing, so a fresh clone
# without a config.ini won't crash - keys just come back as None.
_parser.read(_CONFIG_PATH)


def get_api_key(name):
    value = _parser.get("api_keys", name, fallback=None)
    return value or None  # turns "" into None