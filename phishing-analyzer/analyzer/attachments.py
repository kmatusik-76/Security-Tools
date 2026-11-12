def get_attachments(msg):
    """
    List the attachments of a message.
    Return example attachments["filename"] = "invoice.pdf"
    """
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if not (part.is_attachment() or part.get_filename()):
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size": len(payload) })
    return attachments