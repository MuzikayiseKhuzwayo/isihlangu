"""State Diff Engine: Verifies whether an attack caused real target state mutations."""

from typing import Any


class StateSnapshot:
    """Represents a state snapshot of target entities or database tables."""

    def __init__(self, entities: dict[str, Any]) -> None:
        self.entities = entities

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StateSnapshot":
        return cls(entities=data.copy())


class StateDiffEngine:
    """Calculates diffs between pre- and post-test states to prove mutations."""

    @staticmethod
    def compute_diff(before: StateSnapshot, after: StateSnapshot) -> dict[str, Any]:
        diff: dict[str, Any] = {
            "created": {},
            "modified": {},
            "deleted": [],
        }

        # Check for additions and modifications
        for key, val_after in after.entities.items():
            if key not in before.entities:
                diff["created"][key] = val_after
            elif before.entities[key] != val_after:
                diff["modified"][key] = {
                    "before": before.entities[key],
                    "after": val_after,
                }

        # Check for deletions
        for key in before.entities:
            if key not in after.entities:
                diff["deleted"].append(key)

        return diff

    @staticmethod
    def has_unauthorized_mutation(
        diff: dict[str, Any], allowed_keys: list[str] | None = None
    ) -> bool:
        """Returns True if state changed in unauthorized records or properties."""
        allowed = set(allowed_keys or [])
        all_changed_keys = (
            set(diff["created"].keys()) | set(diff["modified"].keys()) | set(diff["deleted"])
        )
        unauthorized = all_changed_keys - allowed
        return len(unauthorized) > 0
