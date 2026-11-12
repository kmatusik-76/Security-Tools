from email.utils import parseaddr
import re

SENDER_HEADERS = ("From", "Reply-To", "Return-Path")
AUTH_METHODS = ("spf", "dkim", "dmarc")

def get_sender_addresses(msg):
    '''
    Reads all email addresses from SENDER_HEADERS and parses it using double dictionary, separating domain
    ex. result['from'] = {"address": "support@bank.invalid", "domain": "bank.invalid"}
    '''
    result = {}
    for name in SENDER_HEADERS:
        value=msg[name]
        address = parseaddr(str(value))[1] if value is not None else ""
        if "@" in address:
            domain = address.rpartition("@")[2].lower()
            result[name] = {"address":address, "domain":domain}
        else:
            result[name] = None
    return result

def get_auth_results(msg):
    '''
    Reads the SPF, DKIM and DMARC results from the Authentication-Results.
    Retuns dict with AUTH_METHODS as keys
    ex. result['spf']='fail'
    '''
    result = {method: None for method in AUTH_METHODS}
    value = msg["Authentication-Results"]
    if value is None:
        return result
    for method in AUTH_METHODS:
        match = re.search(rf"\b{method}\s*=\s*([a-z]+)", str(value), re.IGNORECASE)
        if match:
            result[method] = match.group(1).lower()
    return result