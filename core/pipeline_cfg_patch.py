#!/usr/bin/env python3
# core/pipeline_cfg_patch.py — cfg shim so modules can call self.p.cfg.get()

class CfgShim:
    """Allows modules to call self.p.cfg.get('key', default) safely."""
    def __init__(self, args, config_obj=None):
        self._args   = args
        self._config = config_obj

    def get(self, key, default=None):
        # 1. Try config file first
        if self._config:
            val = self._config.get(key)
            if val is not None:
                return val
        # 2. Try args namespace
        val = getattr(self._args, key, None)
        if val is not None:
            return val
        return default
