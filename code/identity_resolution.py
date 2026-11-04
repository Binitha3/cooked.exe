"""Deterministic intent classification and as-of identity resolution.

The module has no third-party dependencies.  Intent classification is kept
behind a small rules backend so a separately configured classifier can be
introduced later without changing identity resolution or the output contract.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import re
import unicodedata
from typing import Iterable, Literal, Mapping, Protocol

from .contracts import (
    IdentityIdentifier,
    IdentityProvenance,
    Intent,
    IntentDecision,
    ResolutionStatus,
    ResolvedSubject,
)


IdentifierKind = Literal["email", "phone", "email_hash"]

_IDENTIFIER_FIELDS: tuple[IdentifierKind, ...] = ("email", "phone", "email_hash")
_REQUIRED_IDENTITY_FIELDS = ("user_id", "name", "email", "phone", "email_hash", "updated_at")
_REQUIRED_AUDIT_FIELDS = ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value")


class IntentClassifier(Protocol):
    """Backend interface for replacing or wrapping the built-in rules."""

    def classify(self, request_text: str) -> IntentDecision:
        ...


def _normalize_email(value: str) -> str:
    """Normalize only surrounding whitespace, Unicode form, and letter case."""

    return unicodedata.normalize("NFC", value.strip()).casefold()


def _normalize_identifier(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "email":
        return _normalize_email(value)
    if kind == "email_hash":
        # Hexadecimal hashes are case-insensitive as represented strings.
        return value.casefold()
    return value


def _valid_email(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = _normalize_email(value)
    if not normalized or any(ch.isspace() for ch in normalized) or normalized.count("@") != 1:
        return False
    local, domain = normalized.split("@", 1)
    return bool(local and domain)


def _parse_utc(value: object) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            return None
        try:
            return value.astimezone(timezone.utc)
        except (OverflowError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _row_string(row: Mapping[str, object], field_name: str) -> str | None:
    value = row.get(field_name)
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def _dedupe_provenance(items: Iterable[IdentityProvenance]) -> tuple[IdentityProvenance, ...]:
    output: list[IdentityProvenance] = []
    seen: set[tuple[str, str | None, datetime | None, str | None]] = set()
    for item in items:
        key = (item.source, item.audit_id, item.event_time, item.field_name)
        if key not in seen:
            seen.add(key)
            output.append(item)
    return tuple(output)


def _ambiguous(
    reason: str,
    candidates: Iterable[str] = (),
    provenance: Iterable[IdentityProvenance] = (),
) -> ResolvedSubject:
    candidate_count = len(set(candidates))
    explanation = reason
    if candidate_count:
        explanation = f"{reason} ({candidate_count} candidate user(s))"
    return ResolvedSubject(
        resolution_status=ResolutionStatus.AMBIGUOUS,
        user_id=None,
        identity_provenance=_dedupe_provenance(provenance),
        resolution_explanation=explanation,
    )


def _unresolved(
    reason: str,
    provenance: Iterable[IdentityProvenance] = (),
) -> ResolvedSubject:
    return ResolvedSubject(
        resolution_status=ResolutionStatus.UNRESOLVED,
        user_id=None,
        identity_provenance=_dedupe_provenance(provenance),
        resolution_explanation=reason,
    )


def _validate_identity_chains(
    user_id: str,
    cutoff: datetime,
    snapshot: Mapping[str, object] | None,
    audit_rows: list[Mapping[str, object]],
) -> tuple[dict[str, tuple[str, datetime | None]], tuple[IdentityIdentifier, ...], list[IdentityProvenance], list[str]]:
    """Return as-of current fields, historical intervals, provenance, and problems."""

    problems: list[str] = []
    audit_provenance: list[IdentityProvenance] = []
    current: dict[str, tuple[str, datetime | None]] = {}
    historical: list[IdentityIdentifier] = []
    snapshot_time = _parse_utc(snapshot.get("updated_at")) if snapshot is not None else None

    if snapshot is not None and snapshot_time is None:
        problems.append("identity snapshot has a missing or malformed updated_at")

    unsupported_fields = {
        str(row.get("field_name"))
        for row in audit_rows
        if row.get("field_name") not in _IDENTIFIER_FIELDS
    }
    if unsupported_fields:
        problems.append("audit row contains an unsupported identifier field")

    for kind in _IDENTIFIER_FIELDS:
        events: list[tuple[datetime, str, str, str, Mapping[str, object]]] = []
        for row in audit_rows:
            if row.get("field_name") != kind:
                continue
            event_time = _parse_utc(row.get("event_time"))
            old_value = _row_string(row, "old_value")
            new_value = _row_string(row, "new_value")
            audit_id = _row_string(row, "audit_id")
            if event_time is None:
                problems.append(f"{kind} audit event has a missing or malformed event_time")
                continue
            if event_time > cutoff:
                continue
            if old_value is None or new_value is None or audit_id is None:
                problems.append(f"{kind} audit event has a missing identifier value or audit_id")
                continue
            events.append((event_time, audit_id, old_value, new_value, row))
            audit_provenance.append(
                IdentityProvenance(
                    source="user_audit_log.csv",
                    audit_id=audit_id,
                    event_time=event_time,
                    field_name=kind,
                )
            )

        events.sort(key=lambda item: (item[0], item[1]))
        for first, second in zip(events, events[1:]):
            if first[0] == second[0]:
                # Same-time sequential changes cannot be ordered from timestamps.
                problems.append(f"{kind} audit events share a timestamp")
            if _normalize_identifier(kind, first[3]) != _normalize_identifier(kind, second[2]):
                problems.append(f"{kind} audit chain is broken")

        snapshot_value = _row_string(snapshot, kind) if snapshot is not None else None
        if snapshot is not None and snapshot_value is None:
            problems.append(f"identity snapshot has a missing {kind}")

        current_valid_from: datetime | None = None
        if snapshot is not None and snapshot_time is not None:
            before_or_at = [event for event in events if event[0] <= snapshot_time]
            after_snapshot = [event for event in events if event[0] > snapshot_time]
            if before_or_at and snapshot_value is not None:
                last_before = before_or_at[-1]
                if _normalize_identifier(kind, last_before[3]) != _normalize_identifier(kind, snapshot_value):
                    problems.append(f"{kind} snapshot conflicts with its latest prior audit event")
            if after_snapshot and snapshot_value is not None:
                if _normalize_identifier(kind, after_snapshot[0][2]) != _normalize_identifier(kind, snapshot_value):
                    problems.append(f"{kind} audit event does not continue from the snapshot")
                current[kind] = (after_snapshot[-1][3], after_snapshot[-1][0])
                current_valid_from = after_snapshot[-1][0]
            elif snapshot_value is not None:
                current[kind] = (snapshot_value, before_or_at[-1][0] if before_or_at else None)
                current_valid_from = before_or_at[-1][0] if before_or_at else None
            audit_provenance.append(
                IdentityProvenance(
                    source="user_identities.csv",
                    event_time=snapshot_time,
                    field_name=kind,
                )
            )
        elif events:
            # A snapshot after the cutoff is intentionally ignored.  Eligible
            # history alone can establish a field's current value only when it
            # contains a change at or before the cutoff.
            current[kind] = (events[-1][3], events[-1][0])
            current_valid_from = events[-1][0]

        if events:
            first = events[0]
            historical.append(
                IdentityIdentifier(
                    identifier_type=kind,
                    value=first[2],
                    valid_from=None,
                    valid_to=first[0],
                )
            )
            for index, event in enumerate(events[:-1]):
                following = events[index + 1]
                historical.append(
                    IdentityIdentifier(
                        identifier_type=kind,
                        value=event[3],
                        valid_from=event[0],
                        valid_to=following[0],
                    )
                )

        if kind in current and current_valid_from is not None:
            # Current values are added below; the timestamp is retained in the
            # temporary map so the contract can record when this value began.
            current[kind] = (current[kind][0], current_valid_from)

    historical_identifiers = tuple(
        identifier
        for identifier in historical
        if identifier.valid_to is not None
        and identifier.valid_to <= cutoff
    )
    return current, historical_identifiers, audit_provenance, problems


def resolve_identity(
    request_email: str,
    requested_at: datetime | str,
    audit_at: datetime | str,
    identities: Iterable[Mapping[str, object]],
    audit_log: Iterable[Mapping[str, object]],
) -> ResolvedSubject:
    """Resolve a request email to one user and reconstruct identifiers as of ``audit_at``.

    Only identity snapshots whose ``updated_at`` is at or before ``audit_at``
    and audit events whose ``event_time`` is at or before it are considered.
    Historical email aliases are matched through eligible email audit events.
    Any conflicting match or relevant broken history returns AMBIGUOUS.
    """

    if not _valid_email(request_email):
        return _unresolved("request_email is missing or malformed")
    request_time = _parse_utc(requested_at)
    cutoff = _parse_utc(audit_at)
    if request_time is None:
        return _unresolved("requested_at is missing, malformed, or timezone-naive")
    if cutoff is None:
        return _unresolved("audit_at is missing, malformed, or timezone-naive")
    if request_time > cutoff:
        return _unresolved("requested_at is later than audit_at")

    try:
        identity_rows = list(identities)
        audit_rows = list(audit_log)
    except TypeError:
        return _unresolved("identity and audit inputs must be iterable rows")

    snapshots: dict[str, Mapping[str, object]] = {}
    malformed_snapshot_users: set[str] = set()
    uncertain_candidates: set[str] = set()
    candidate_provenance: dict[str, list[IdentityProvenance]] = defaultdict(list)
    for row in identity_rows:
        if not isinstance(row, Mapping):
            continue
        user_id = _row_string(row, "user_id")
        if user_id is None:
            continue
        updated_at = _parse_utc(row.get("updated_at"))
        if updated_at is None:
            malformed_snapshot_users.add(user_id)
            snapshot_email = _row_string(row, "email")
            if snapshot_email is not None and _normalize_email(snapshot_email) == _normalize_email(request_email):
                uncertain_candidates.add(user_id)
                candidate_provenance[user_id].append(
                    IdentityProvenance(
                        source="user_identities.csv:undated_email_match",
                        field_name="email",
                    )
                )
            continue
        if updated_at > cutoff:
            continue
        if user_id in snapshots:
            return _ambiguous("multiple eligible identity snapshots exist for a user", (user_id,))
        if any(_row_string(row, required) is None for required in _REQUIRED_IDENTITY_FIELDS):
            malformed_snapshot_users.add(user_id)
        snapshots[user_id] = row

    normalized_email = _normalize_email(request_email)
    candidates: set[str] = set()
    eligible_audits_by_user: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    malformed_audit_users: set[str] = set()

    for row in audit_rows:
        if not isinstance(row, Mapping):
            continue
        user_id = _row_string(row, "user_id")
        event_time = _parse_utc(row.get("event_time"))
        if event_time is None:
            if user_id is not None:
                malformed_audit_users.add(user_id)
                if row.get("field_name") == "email":
                    for value_field in ("old_value", "new_value"):
                        value = _row_string(row, value_field)
                        if value is not None and _normalize_email(value) == normalized_email:
                            uncertain_candidates.add(user_id)
                            candidate_provenance[user_id].append(
                                IdentityProvenance(
                                    source="user_audit_log.csv:undated_email_match",
                                    audit_id=_row_string(row, "audit_id"),
                                    field_name="email",
                                )
                            )
            continue
        if event_time > cutoff:
            continue
        if user_id is None:
            continue
        if any(_row_string(row, required) is None for required in _REQUIRED_AUDIT_FIELDS):
            malformed_audit_users.add(user_id)
        eligible_audits_by_user[user_id].append(row)
        if row.get("field_name") == "email":
            for value_field, side in (("old_value", "old"), ("new_value", "new")):
                value = _row_string(row, value_field)
                if value is not None and _normalize_email(value) == normalized_email:
                    candidates.add(user_id)
                    audit_id = _row_string(row, "audit_id")
                    candidate_provenance[user_id].append(
                        IdentityProvenance(
                            source=f"user_audit_log.csv:matched_{side}_email",
                            audit_id=audit_id,
                            event_time=event_time,
                            field_name="email",
                        )
                    )

    for user_id, snapshot in snapshots.items():
        snapshot_email = _row_string(snapshot, "email")
        if snapshot_email is not None and _normalize_email(snapshot_email) == normalized_email:
            candidates.add(user_id)
            candidate_provenance[user_id].append(
                IdentityProvenance(
                    source="user_identities.csv:matched_email",
                    event_time=_parse_utc(snapshot.get("updated_at")),
                    field_name="email",
                )
            )

    if not candidates and uncertain_candidates:
        return _ambiguous(
            "only malformed or undated identity evidence matches the request email",
            uncertain_candidates,
            (item for user in uncertain_candidates for item in candidate_provenance[user]),
        )
    candidates.update(uncertain_candidates)
    if not candidates:
        return _unresolved("no eligible current or historical email match")
    if len(candidates) > 1:
        return _ambiguous(
            "request email maps to multiple users using eligible evidence",
            candidates,
            (item for user in candidates for item in candidate_provenance[user]),
        )

    user_id = next(iter(candidates))
    match_provenance = candidate_provenance[user_id]
    if user_id in malformed_snapshot_users:
        return _ambiguous("matched user's eligible identity snapshot is malformed", candidates, match_provenance)
    if user_id in malformed_audit_users:
        return _ambiguous(
            "matched user has an eligible audit row with missing or malformed fields",
            candidates,
            match_provenance,
        )

    current, historical, audit_provenance, problems = _validate_identity_chains(
        user_id,
        cutoff,
        snapshots.get(user_id),
        eligible_audits_by_user.get(user_id, []),
    )
    provenance = _dedupe_provenance((*match_provenance, *audit_provenance))
    if problems:
        return _ambiguous("; ".join(dict.fromkeys(problems)), candidates, provenance)

    current_identifiers = tuple(
        IdentityIdentifier(identifier_type=kind, value=current[kind][0], valid_from=current[kind][1])
        for kind in _IDENTIFIER_FIELDS
        if kind in current
    )
    return ResolvedSubject(
        resolution_status=ResolutionStatus.UNIQUE,
        user_id=user_id,
        current_identifiers=current_identifiers,
        historical_identifiers=historical,
        identity_provenance=provenance,
        resolution_explanation="The request email maps to one subject using eligible identity evidence.",
    )


_EN_DELETE = re.compile(
    r"\b(?:delete|deletes|deleting|deleted|erase|erases|erasing|erased|remove|removes|"
    r"removing|removed|wipe|wipes|wiping|wiped|purge|purges|purging|purged|forget|"
    r"forgets|forgot|forgotten|erasure|deletion)\b",
    re.I,
)
_EN_NEGATED = re.compile(
    r"\b(?:i\s+|we\s+)?(?:do\s+not|did\s+not|have\s+not|don't|didn't|haven't|dont|never)\s+"
    r"(?:(?:want|wish|need)\s+(?:you\s+to\s+)?)?"
    r"(?:delete|erase|remove|wipe|purge|forget)\b[^.!?;,]*"
    r"|\b(?:i\s+|we\s+)?(?:do\s+not|did\s+not|have\s+not|don't|didn't|haven't|dont)\s+"
    r"(?:request|want|authorize|consent\s+to)\b[^.!?;,]*"
    r"|\b(?:i\s+|we\s+)?(?:do\s+not|don't|dont)\s+want\s+"
    r"(?:my\s+|the\s+)?(?:account|data|profile|information)\b[^.!?;]*?"
    r"\b(?:deleted|erased|removed)\b[^.!?;]*"
    r"|\bnot\s+(?:a\s+)?(?:deletion|erasure)\b[^.!?;]*",
    re.I,
)
_EN_REQUEST = re.compile(
    r"\b(?:please|kindly|request(?:ing)?|ask(?:ing)?|want|would\s+like|"
    r"could\s+you|can\s+you|i'd\s+like|i\s+am\s+requesting)\b",
    re.I,
)
_EN_TARGET = re.compile(
    r"\b(?:my|our|personal|account|profile|customer|user)\s+"
    r"(?:account|profile|data|information|details|records|identity)?\b|"
    r"\b(?:my\s+data|my\s+information|my\s+account|me)\b",
    re.I,
)
_EN_DIRECTIVE = re.compile(r"^\s*(?:please\s+)?(?:delete|erase|remove|wipe|purge|forget)\b", re.I)
_EN_NON_DELETE = re.compile(
    r"\b(?:access|view|see|copy|export|download|portability|correct|correction|"
    r"update|change|replace|rectify|unsubscribe|subscription|opt\s*out|marketing|"
    r"stop\s+(?:sending|receiving)|do\s+not\s+contact)\b",
    re.I,
)
_EN_MAILING_TARGET = re.compile(
    r"\b(?:mailing\s+list|newsletter|promotional\s+messages?|marketing\s+emails?)\b",
    re.I,
)
_EN_PERSONAL_DATA_TARGET = re.compile(
    r"\b(?:my|our|personal|account|profile|user|customer)\s+"
    r"(?:personal\s+)?(?:data|information|details|records|account|profile|identity)\b|"
    r"\bmy\s+(?:account|profile|data|information|records)\b",
    re.I,
)

_CJK_DELETE = ("删除", "刪除", "清除", "消去", "抹消", "削除", "삭제", "지우", "파기")
_CJK_NEGATED = (
    "不要删除", "不要刪除", "请勿删除", "請勿刪除", "不想删除", "不想刪除",
    "不希望删除", "不希望刪除", "不需要删除", "不需要刪除", "不是删除", "不是刪除",
    "削除しないで", "削除したくない", "削除を希望しません", "削除は希望しません",
    "消去しないで", "消去したくない", "削除不要", "삭제하지 마", "삭제하지 말",
    "삭제하고 싶지 않", "삭제를 원하지 않", "삭제는 원하지 않", "삭제할 필요 없",
    "삭제 요청이 아닙니다", "지우지 마", "파기하지 마",
)
_CJK_REQUEST = (
    "请求", "請求", "请帮", "請幫", "麻烦", "麻煩", "希望", "お願いします", "依頼",
    "してください", "していただけ", "したい", "요청", "주세요", "부탁", "바랍니다",
    "원합니다", "하고 싶습니다", "해 주세요", "해주세", "해 주시", "영구 삭제",
)
_CJK_TARGET = (
    "账户", "帳戶", "账号", "帳號", "個人情報", "個人データ", "アカウント", "データ",
    "계정", "개인정보", "데이터", "정보", "我的", "我的账户", "我的帳戶",
)
_CJK_NON_DELETE = (
    "访问", "訪問", "查看", "查阅", "查閱", "获取副本", "獲取副本", "导出", "導出", "下载", "下載",
    "更正", "修改", "更新", "退订", "退訂", "取消订阅", "取消訂閱", "停止营销邮件", "停止行销邮件",
    "アクセス", "閲覧", "開示", "確認", "訂正", "修正", "更新", "エクスポート", "ダウンロード",
    "配信停止", "配信解除", "열람", "접근", "조회", "정정", "수정", "변경", "내보내기",
    "다운로드", "수신 거부", "구독 취소", "마케팅 이메일 중지",
)

# Common participant-language cues in Romance languages.  These are broad
# vocabulary signals, not templates tied to any dataset row or label.
_INTL_DELETE = (
    "exclusão", "exclusao", "eliminação", "eliminacion", "eliminación", "apagar", "excluir",
    "deletar", "supressão", "supressao", "apagamento", "supresión", "borrado", "borrar",
    "suprimir", "suppression", "effacement", "supprimer", "effacer", "effacez", "effaçage",
)
_INTL_NEGATED = (
    "não quero excluir", "nao quero excluir", "não quero apagar", "nao quero apagar",
    "não solicito a exclusão", "nao solicito a exclusao", "não solicito exclusão", "nao solicito exclusao",
    "no quiero eliminar", "no quiero borrar", "no solicito la eliminación", "no solicito la eliminacion",
    "no solicito la eliminación", "no solicito la eliminacion", "no pido la eliminación", "no pido la eliminacion",
    "ne pas supprimer", "ne pas effacer", "ne souhaite pas la suppression", "ne demande pas la suppression",
    "ne demande pas l'effacement", "je ne veux pas supprimer", "je ne veux pas l'effacement",
)
_INTL_REQUEST = (
    "solicito", "solicitação", "solicitacao", "peço", "peco", "quero", "por favor", "gostaria",
    "solicito", "solicitud", "pido", "quiero", "quisiera", "por favor", "solicite",
    "je demande", "je souhaite", "je voudrais", "je veux", "veuillez", "merci de",
)
_INTL_TARGET = (
    "conta", "dados", "informações", "informacoes", "informação", "informacao", "perfil", "e-mail",
    "cuenta", "datos", "información", "informacion", "correo", "perfil", "cuenta asociada",
    "compte", "données", "donnees", "informations", "profil", "adresse e-mail",
)
_INTL_NON_DELETE = (
    "acesso", "acessar", "cópia", "copia", "exportar", "baixar", "corrigir", "atualizar", "cancelar assinatura",
    "acceso", "acceder", "copia", "exportar", "descargar", "corregir", "actualizar", "cancelar suscripción",
    "accès", "acceder", "copie", "exporter", "télécharger", "corriger", "mettre à jour", "désabonner",
)
_INTL_MAILING_TARGET = (
    "lista de e-mails", "lista de emails", "mensagens de marketing", "correos promocionales",
    "lista de correo", "liste de diffusion", "courriels marketing", "emails de marketing",
)
_INTL_PERSONAL_TARGET = (
    "meus dados", "meus dados pessoais", "minhas informações", "minhas informacoes", "minha conta",
    "mis datos", "mis datos personales", "mi cuenta", "mis datos personales", "mi información", "mi informacion",
    "mes données", "mes donnees", "mes informations", "mon compte", "mon profil",
)


class _RulesIntentClassifier:
    """Language-aware deterministic fallback; no sample labels or case data."""

    @staticmethod
    def classify(request_text: str) -> IntentDecision:
        if not isinstance(request_text, str) or not request_text.strip():
            return IntentDecision(Intent.AMBIGUOUS, "request text is missing or malformed")

        normalized = unicodedata.normalize("NFKC", request_text).casefold()
        negated = (
            bool(_EN_NEGATED.search(normalized))
            or any(term in normalized for term in _CJK_NEGATED)
            or any(term in normalized for term in _INTL_NEGATED)
        )
        if negated:
            remainder = _EN_NEGATED.sub(" ", normalized)
            for term in (*_CJK_NEGATED, *_INTL_NEGATED):
                remainder = remainder.replace(term, " ")
            # A negated deletion plus a separate positive deletion request is
            # contradictory, so leave it for review rather than choosing one.
            other_positive = bool(_EN_DELETE.search(remainder)) or any(
                term in remainder for term in _CJK_DELETE
            )
            if other_positive:
                return IntentDecision(Intent.AMBIGUOUS, "request contains both negated and positive deletion language")
            return IntentDecision(Intent.NOT_DELETE, "request explicitly declines or negates deletion")

        english_delete = bool(_EN_DELETE.search(normalized))
        cjk_delete = any(term in normalized for term in _CJK_DELETE)
        intl_delete = any(term in normalized for term in _INTL_DELETE)
        if english_delete:
            if (
                _EN_MAILING_TARGET.search(normalized)
                and not _EN_PERSONAL_DATA_TARGET.search(normalized)
            ):
                return IntentDecision(Intent.NOT_DELETE, "request only removes the requester from a mailing or marketing list")
            request_signal = bool(_EN_REQUEST.search(normalized))
            target_signal = bool(_EN_TARGET.search(normalized))
            if request_signal or target_signal or _EN_DIRECTIVE.search(normalized):
                return IntentDecision(Intent.DELETE, "explicit deletion language is directed at the requester or their data")
            return IntentDecision(Intent.AMBIGUOUS, "deletion is mentioned without a clear personal request")

        if cjk_delete:
            request_signal = any(term in normalized for term in _CJK_REQUEST)
            target_signal = any(term in normalized for term in _CJK_TARGET)
            if request_signal or target_signal:
                return IntentDecision(Intent.DELETE, "non-English text requests deletion of an account or personal data")
            return IntentDecision(Intent.AMBIGUOUS, "non-English deletion language lacks a clear request or target")

        if intl_delete:
            if any(term in normalized for term in _INTL_MAILING_TARGET) and not any(
                term in normalized for term in _INTL_PERSONAL_TARGET
            ):
                return IntentDecision(Intent.NOT_DELETE, "request only concerns a mailing or marketing list")
            request_signal = any(term in normalized for term in _INTL_REQUEST)
            target_signal = any(term in normalized for term in _INTL_TARGET)
            if request_signal or target_signal:
                return IntentDecision(Intent.DELETE, "non-English text requests deletion of an account or personal data")
            return IntentDecision(Intent.AMBIGUOUS, "non-English deletion language lacks a clear request or target")

        if (
            _EN_NON_DELETE.search(normalized)
            or any(term in normalized for term in _CJK_NON_DELETE)
            or any(term in normalized for term in _INTL_NON_DELETE)
        ):
            return IntentDecision(Intent.NOT_DELETE, "request asks for a non-deletion privacy action")

        return IntentDecision(Intent.AMBIGUOUS, "request does not clearly authorize or reject deletion")


_DEFAULT_INTENT_CLASSIFIER: IntentClassifier = _RulesIntentClassifier()


def classify_deletion_request(request_text: str) -> IntentDecision:
    """Classify deletion intent without consulting workflow status or case labels.

    The built-in backend handles English, Japanese, Korean, and common
    Simplified/Traditional Chinese privacy terms.  ``IntentClassifier`` is the
    extension point for an optional model-backed classifier.
    """

    return _DEFAULT_INTENT_CLASSIFIER.classify(request_text)
