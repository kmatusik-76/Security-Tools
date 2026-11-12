import re
from urllib.parse import urlsplit 

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
TRAILING_PUNCTATION = ".,;:!?)"

def get_links(msg):
    '''
    Extracts all http/https URLs from the text part of a message.
    Example: ["http://secure-bank.invalid.login-check.invalid/verify?id=12345"]
    '''
    links=[]
    for part in msg.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        if part.is_attachment():
            continue
        for url in URL_PATTERN.findall(part.get_content()):
            links.append(url.rstrip(TRAILING_PUNCTATION))
    return list(dict.fromkeys(links))

def get_link_host(url):
    '''
    Return the host a url points to.
    Returns the host lowercased or an IP address.
    '''
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None