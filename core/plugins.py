import os
import importlib
from core.database import add_ip, add_plugin_result

PLUGIN_FOLDER = "plugins"

def make_save_function(scan_id, plugin_name):
    def save(key, value, ip):
        ip_id = add_ip(ip)
        add_plugin_result(ip_id, plugin_name, key, value, scan_id)
    return save


def load_plugins():
    plugins = []
    for fname in os.listdir(PLUGIN_FOLDER):
        if fname.endswith(".py") and fname != "__init__.py":
            modname = fname[:-3]
            module = importlib.import_module(f"{PLUGIN_FOLDER}.{modname}")
            plugins.append((modname, module))
    return plugins
