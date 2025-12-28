#!/usr/bin/env python3
import sys
#from header_rewriter import HeaderRewriter
from dkim_aware_header_rewriter import DKIMAwareHeaderRewriter
class ForwardRewriter(DKIMAwareHeaderRewriter):

    def __init__(self, original_recipient: str, real_recipient: str):
        self.pseudonym = original_recipient
        self.real = real_recipient

    @DKIMAwareHeaderRewriter.handles("X-Forwarded-To")
    def rewrite_forwarded_to(self, line: str) -> str:
        return f"X-Forwarded-To: {self.real}"

    @DKIMAwareHeaderRewriter.handles("X-Forwarded-For")
    def rewrite_forwarded_for(self, name: str, value: str) -> str:
        if value:
            return f"X-Forwarded-For: {value}, {self.pseudonym}"
        else:
            return f"X-Forwarded-For: {self.pseudonym}"

    @DKIMAwareHeaderRewriter.handles("To")
    def rewrite_to(self, name: str, value: str) -> str:
        return f"To: {self.real}"