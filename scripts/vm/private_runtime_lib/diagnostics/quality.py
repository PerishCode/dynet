from __future__ import annotations


def quality_acceptance_checks(
    report: dict,
    route_non_direct_fallback: bool = False,
) -> list[dict]:
    selection = report.get("_selectionBrief", {})
    bound = selection.get("boundSelection", {}) if isinstance(selection, dict) else {}
    if route_non_direct_fallback:
        fallback_sets = int(bound.get("fallbackCandidateSets") or 0)
        return [
            check("quality-bound-candidate-set", fallback_sets > 0),
            check(
                "quality-bound-selected",
                int(bound.get("attemptCandidateSets") or 0)
                >= int(bound.get("candidateSets") or 0) + fallback_sets,
            ),
            check(
                "quality-bound-selected-has-quality",
                int(bound.get("fallbackSelectedWithQuality") or 0) == fallback_sets,
            ),
            check("quality-bound-selected-best", fallback_selected_best(bound) > 0),
        ]
    return [
        check("quality-bound-candidate-set", int(bound.get("candidateSets") or 0) > 0),
        check(
            "quality-bound-selected",
            int(bound.get("withBoundSelected") or 0) == int(bound.get("candidateSets") or 0),
        ),
        check(
            "quality-bound-selected-has-quality",
            int(bound.get("selectedWithQuality") or 0) == int(bound.get("candidateSets") or 0),
        ),
        check("quality-bound-selected-best", int(bound.get("selectedBehind") or 0) == 0),
    ]


def fallback_selected_best(bound: dict) -> int:
    rows = bound.get("rows")
    if not isinstance(rows, list):
        return 0
    return sum(
        1
        for row in rows
        if isinstance(row, dict)
        and row.get("selectionRole") == "fallback"
        and row.get("selectedBest") is True
    )


def check(name: str, passed: bool) -> dict:
    return {"name": name, "passed": bool(passed)}
