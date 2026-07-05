"""Same shape as vulnerable_idor.py but actually safe: ownership is checked
before the sensitive action. Used to verify the AI reasoning pass does NOT
flag correct code just because it superficially resembles the vulnerable
version (i.e. it's not pattern-matching on function names/shape).
"""


class PermissionDenied(Exception):
    pass


def get_document(document_id):
    return {"id": document_id, "owner_id": 42, "content": "secret notes"}


def delete_document(request, document_id):
    """DELETE /documents/<document_id> -- checks ownership before deleting."""
    document = get_document(document_id)
    if document["owner_id"] != request.user.id:
        raise PermissionDenied("You do not own this document")
    document["deleted"] = True
    return {"status": "deleted", "id": document_id}


def update_document_title(request, document_id, new_title):
    """PATCH /documents/<document_id>/title -- checks ownership too."""
    document = get_document(document_id)
    if document["owner_id"] != request.user.id:
        raise PermissionDenied("You do not own this document")
    document["title"] = new_title
    return document
