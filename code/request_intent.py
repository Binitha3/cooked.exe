"""Integration-owned authorization adapter for deletion audits.

The identity module's classifier intentionally distinguishes DELETE,
NOT_DELETE, and AMBIGUOUS. This adapter adds the separate task-authorized
case of verifying a previously reported deletion without authorizing new
destructive remediation.
"""

from __future__ import annotations

import re
from typing import Callable

from .contracts import Intent, IntentDecision


_VERIFICATION_ACTION = re.compile(r"\b(?:check|confirm|verify|audit|review|inspect)\b", re.I)
_PRIOR_CONTEXT = re.compile(
    r"\b(?:old|previous|prior|earlier)\s+(?:report|request|deletion|privacy request|audit|review|status)\b"
    r"|\b(?:already|previously)\s+(?:requested|submitted|filed)\b.{0,80}\b(?:delet\w*|eras\w*|remov\w*)\b"
    r"|\b(?:submitted|filed|made)\s+(?:an?\s+)?(?:deletion|erasure|removal)\s+(?:request|ticket)\b",
    re.I,
)
_DELETION_OUTCOME = re.compile(
    r"\b(?:gone|deleted|removed|erased|wiped|completed|complete)\b"
    r"|\bno longer\s+(?:exists?|identifiable|linked)\b"
    r"|\b(?:cannot|can't|can not)\s+(?:identify|link)\b"
    r"|\bno remaining\s+(?:records?|copies?)\b",
    re.I,
)
_NEW_DESTRUCTIVE_DIRECTIVE = re.compile(
    r"\b(?:please|kindly|i want you to|i need you to|i request you to|can you|could you)\s+"
    r"(?:permanently\s+)?(?:delete|remove|erase|wipe|close|purge)\b"
    r"|\b(?:delete|remove|erase|wipe|close|purge)\s+(?:all\s+)?(?:my\s+)?"
    r"(?:account|profile|personal data|data|records?|copies?)\b",
    re.I,
)
_NEGATED_DESTRUCTIVE_DIRECTIVE = re.compile(
    r"\b(?:do not|don't|never|not)\s+(?:delete|remove|erase|wipe|close|purge)\b",
    re.I,
)


def classify_request_intent(
    request_text: str,
    base_classifier: Callable[[str], IntentDecision] | None = None,
) -> IntentDecision:
    """Classify whether the request authorizes deletion, verification, or neither.

    Verification-only requires all three signals: a verification action, a
    reference to a prior report/request, and a deletion postcondition. A new
    destructive directive keeps the base classifier's decision. Generic data
    questions and ambiguous requests also keep the base classifier's decision.
    """
    if base_classifier is None:
        from .identity_resolution import classify_deletion_request

        base_classifier = classify_deletion_request

    base = base_classifier(request_text)
    if not isinstance(request_text, str) or not request_text.strip():
        return base

    if (
        _VERIFICATION_ACTION.search(request_text)
        and _PRIOR_CONTEXT.search(request_text)
        and _DELETION_OUTCOME.search(request_text)
        and not _NEW_DESTRUCTIVE_DIRECTIVE.search(request_text)
        and not _NEGATED_DESTRUCTIVE_DIRECTIVE.search(request_text)
    ):
        return IntentDecision(
            Intent.VERIFY_ONLY,
            "request authorizes verification of a previously reported deletion state, not new destructive remediation",
        )
    return base


__all__ = ["classify_request_intent"]
