#!/usr/bin/env python3
import sys
import inspect
from exceptions import AbortException

#Note: currently can only handle headers appearing at most once
class HeaderRewriter:
    _header_handlers_base = {}

    def _init_handlers(self):
        if not hasattr(self, '_header_rewriter_inited'):
            self._header_handlers = self._header_handlers_base.copy()
            self._header_rewriter_inited = True

    def __init__(self):
        self._init_handlers()

    #Todo: Warn if only line but multiple header_names
    #      Ev add a optional boolean alla call if missing
    #      
    @classmethod
    def handles(cls, *header_names, handleMissing=True):
        def decorator(func):
            for name in header_names:
                cls._header_handlers_base[name.lower()] = (func, handleMissing)
            return func
        return decorator

    def process_header_line(self, name: str, value: str, line: str) -> str:
        self._init_handlers()
        handler, _ = self._header_handlers.get(name.lower(), (None,None))
        self._header_handlers.pop(name.lower(),None)
        if handler:
            sig = inspect.signature(handler)
            params = list(sig.parameters.values())
            if len(params) == 2:
                # Pass the whole line
                return handler(self, line)
            elif len(params) >= 3:
                # Pass name and value separately
                return handler(self, name, value)
            else:
                raise AbortException("Handler must accept at least 1 argument (excluding self)")
        return line

    def add_missing_headers(self, writer):
        self._init_handlers()
        for name, (handler, handleMissing) in self._header_handlers.items():
            if not handleMissing:
                continue
            sig = inspect.signature(handler)
            params = list(sig.parameters.values())
            if len(params) == 2:
                # Pass the whole line as None
                new_line = handler(self, None)
            elif len(params) >= 3:
                # Pass the name but the value as None
                new_line = handler(self, name, None)
            else:
                raise AbortException("Handler must accept at least 1 argument (excluding self)")    
            if new_line:
                writer.write(f"{new_line}\n".encode())