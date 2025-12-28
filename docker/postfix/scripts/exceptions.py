class RetryException(Exception):
    """Raised on an Error, that could be temporary"""
    pass
	
class AbortException(Exception):
    """Raised on an Error, that is permanent"""
    pass