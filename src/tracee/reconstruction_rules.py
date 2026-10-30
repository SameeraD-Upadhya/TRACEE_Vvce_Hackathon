"""Versioned conservative built-in reconstruction rules."""

from __future__ import annotations

from dataclasses import dataclass

from .hypotheses import InferenceRule

EVENT_TYPE_ATTRIBUTE = "event_type"


@dataclass(frozen=True)
class BuiltinRule:
    rule: InferenceRule
    supported_source_types: tuple[str, ...]
    assumptions: tuple[str, ...]


def _rule(source_type: str) -> BuiltinRule:
    return BuiltinRule(
        rule=InferenceRule(
            rule_id=f"same-user-event-{source_type}",
            version="1.0.0",
            event_type="same_user_event_cluster",
            description=(
                "Groups observations in one analysis that share a user value "
                "and normalized event type within the configured time window."
            ),
            required_observation_types=(source_type,),
            required_attributes=("user", EVENT_TYPE_ATTRIBUTE),
            minimum_supporting_observations=2,
            limitations=(
                "Equal usernames do not establish that the same person or host was involved.",
                "Temporal grouping is a candidate only and does not establish causality or an incident.",
                "Observations without a known bounded timestamp cannot be grouped.",
            ),
        ),
        supported_source_types=(source_type,),
        assumptions=(
            "The parser's extracted user value is treated as a grouping key only within this analysis.",
            "The normalized event type is projected from the validated event linked to each observation.",
        ),
    )


BUILTIN_RULES: tuple[BuiltinRule, ...] = (
    _rule("linux_auth"),
    _rule("json_event"),
)


def rules_for_source(source_type: str) -> tuple[BuiltinRule, ...]:
    return tuple(item for item in BUILTIN_RULES if source_type in item.supported_source_types)


def public_rule(item: BuiltinRule) -> dict:
    rule = item.rule
    return {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "description": rule.description,
        "supported_source_types": list(item.supported_source_types),
        "required_attributes": ["user", "event_type"],
        "assumptions": list(item.assumptions),
        "limitations": list(rule.limitations),
        "minimum_supporting_observations": rule.minimum_supporting_observations,
    }
