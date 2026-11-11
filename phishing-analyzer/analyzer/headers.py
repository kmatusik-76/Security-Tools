from email.utils import parseaddr

SENDER_HEADERS = ("From", "Reply-To", "Return-Path")

def get_sender_addresses(msg):
    result = {}
    for name in SENDER_HEADERS:
        value=msg[name]
        address = parseaddr(str(value))[1] if value is not None else ""
        if address:
            domain = address.rpartition("@")[2].lower()
            result[name] = {"address":address, "domain":domain}
        else:
            result[name] = None
    return result