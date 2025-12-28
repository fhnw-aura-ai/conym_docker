#!/usr/bin/env python3
import sys
import inspect
import re
from exceptions import AbortException

#Note: currently can only handle headers appearing at most once
#      currently assumes DKIM signature appears near the begining before customm headers
#      this ususally is true - at the beginning their is the receive & process cahin - then comes the sig then the rest  
class DKIMAwareHeaderRewriter:
    _header_handlers_base = {}

    def _init_handlers(self):
        if not hasattr(self, '_header_rewriter_inited'):
            self._header_handlers = self._header_handlers_base.copy()
            self._protected_headers = set()
            self._header_rewriter_inited = True

    def __init__(self):
        self._init_handlers()

    #Todo: Warn if only line but multiple header_names
    #      Ev add a optional boolean alla call if missing
    #      
    @classmethod
    def handles(cls, *header_names, handle_missing=True):
        def decorator(func):
            for name in header_names:
                cls._header_handlers_base[name.lower()] = (func, handle_missing)
            return func
        return decorator
    
    def _process_DKIM(self, dkim_value: str):
        try:
        # Find the 'h=' field: this captures from 'h=' up to the next semicolon or end
            match = re.search(r'h=([^;]+)', dkim_value, re.IGNORECASE | re.DOTALL)
            if match:
                h_value = match.group(1)
                # Remove any whitespace/newlines and split on colon ':'
                headers = [h.strip().lower() for h in h_value.replace('\n', '').replace('\r', '').split(':')]
                # Filter out empty strings and set the protected headers
                self._protected_headers = set(filter(None, headers))
        except Exception:
            self._protected_headers = set()

    def process_header_line(self, name: str, value: str, line: str) -> str:
        self._init_handlers()
        if name.lower() == "dkim-signature" and not self._protected_headers: self._process_DKIM(value)
        handler, _ = self._header_handlers.get(name.lower(), (None,None)) 
        self._header_handlers.pop(name.lower(),None)
        if handler and name.lower() not in self._protected_headers:
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