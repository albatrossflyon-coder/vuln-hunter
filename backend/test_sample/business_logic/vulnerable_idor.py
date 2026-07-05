"""Fake document API handler with a real broken-access-control bug: any
authenticated user can delete ANY document by ID, because ownership is
never checked. This is invisible to pattern-based static analysis --
there's no dangerous function call, no injection, nothing a regex/AST
rule can flag. It's purely a missing business-logic check.
"""


def get_document(document_id):
    return {"id": document_id, "owner_id": 42, "content": "secret notes"}


def delete_document(request, document_id):
    """DELETE /documents/<document_id> -- any logged-in user can call this."""
    document = get_document(document_id)
    document["deleted"] = True
    return {"status": "deleted", "id": document_id}


def update_document_title(request, document_id, new_title):
    """PATCH /documents/<document_id>/title -- same bug: no ownership check."""
    document = get_document(document_id)
    document["title"] = new_title
    return document
