import re
from html.parser import HTMLParser
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

class _AnchorParser(HTMLParser):
    """Collect (visible text, href) pairs for every <a href="..."> tag."""

    def __init__(self):
        super().__init__()
        self.anchors=[]
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.anchors.append({"text": text, "url": self._href.strip()})
            self._href=None

def get_html_links(msg):
    """Extract links from the HTML parts together with their visible text.
    e.g. <a href="https://evil.invalid">https://bank.invalid</a>.
    This function returns both, so they can be compared later.
    Returns: e.g. [{"text": "https://bank.invalid/login", "url": "https://evil.invalid/x"}]
    """
    anchors = []
    for part in msg.walk():
        if part.get_content_type() != "text/html" or part.is_attachment():
            continue
        parser = _AnchorParser()
        parser.feed(part.get_content())
        parser.close()
        anchors.extend(parser.anchors)
    return anchors