"""Risk rules: each rule looks at extracted facts and returns a finding or None.
A finding is a dict:
    {"rule": str, "score": int, "detail": str}
"rule" is a short identifier, "score" the risk points it adds,
"detail" a human-readable explanation of why it was reported.
"""
AUTH_SCORES = {
    "dmarc": {"fail": 30},
    "spf": {"fail": 15, 'softfail': 5},
    'dkim': {'fail':15}
}


def _related_domains(a, b):
    """
    True if the domains are equal or one is a subdomain of the other.
    """
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def rule_reply_to_mismatch(addresses):
    """Report a Reply-To header pointing to a different domain than From.

    Replies to such a message go to someone else than the visible sender,
    a common trick to collect answers from victims.
    Subdomains count as the same domain (support.bank.invalid ~ bank.invalid).

    Args:
        addresses: dict returned by get_sender_addresses().

    Returns:
        dict: a finding {"rule", "score", "detail"} if the domains differ.
        None if they match, or if From or Reply-To is missing.
    """
    sender = addresses.get("From")
    reply_to = addresses.get("Reply-To")
    if sender is None or reply_to is None:
        return None
    if _related_domains(sender["domain"], reply_to["domain"]):
        return None
    return {
        "rule": "reply_to_mismatch",
        "score": 20,
        "detail": (
            f"Reply-To domain {reply_to['domain']} differs from "
            f"From domain {sender['domain']}"
        ),
    }

def rule_return_path_mismatch(addresses):
    """
    Report a Return-Path in a different domain than from.
    SPF checks the Return-Path domain, not From, so a sender can pass SPF with its own domain
    while showing someone else's in from.

    Args:
        addresses: dict returned by get_sender_addresses()
    
    Returns:
        dict: a finding {"rule", "score", "detail"} if the domains differ.
        None if they match or if From or Return-Path is missing.
    """
    sender = addresses.get("From")
    return_path = addresses.get("Return-Path")
    if sender is None or return_path is None:
        return None
    if _related_domains(sender["domain"], return_path["domain"]):
        return None
    return {
        "rule": "return_path_mismatch",
        "score": 10,
        "detail": (
            f"Return-Path domain {return_path['domain']} differs from "
            f"From domain {sender['domain']}"
        )
    }

def rule_auth_failed(auth):
    """
    Report failed SPF, DKIM, DMARC cheks.
    Severity depends on the method and the result.

    Args:
        auth: dict returned by get_auth_results().

    Returns:
        dict: a finding {"rule", "score", "detail"} with the points of all
        failed checks added up, e.g. detail "dmarc=fail, spf=softfail".
        None if no check failed.
    """
    score = 0
    failed = []
    for method, scores in AUTH_SCORES.items():
        result = auth.get(method)
        if result in scores:
            score += scores[result]
            failed.append(f"{method}={result}")
    if not failed:
        return None
    return {
        "rule": "auth_failed",
        "score": score,
        "detail": "Failed authentication cheks: " + ", ".join(failed),
    }