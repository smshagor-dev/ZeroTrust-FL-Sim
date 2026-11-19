#!/usr/bin/env python3
"""Minimal, exhaustive FL update/revocation ordering counterexample.

This is an abstract two-operation model. It is NOT a proof about a real FL
coordinator, network, storage engine, or prior published protocol.
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

EVENTS = ("update_admission_check", "durable_revocation_ack", "update_commit")


def enumerate_histories(policy: str) -> list[dict[str, object]]:
    if policy not in {"cached_admission", "recheck_at_commit"}:
        raise ValueError(f"unknown policy: {policy}")
    histories: list[dict[str, object]] = []
    for history in itertools.permutations(EVENTS):
        if history.index("update_admission_check") > history.index("update_commit"):
            continue  # A request cannot commit before its initial admission event.
        revoked = False
        cached_authorization: bool | None = None
        update_committed = False
        post_revocation_violation = False
        for event in history:
            if event == "update_admission_check":
                cached_authorization = not revoked
            elif event == "durable_revocation_ack":
                revoked = True
            elif event == "update_commit":
                assert cached_authorization is not None
                authorized = (
                    cached_authorization if policy == "cached_admission" else not revoked
                )
                update_committed = authorized
                post_revocation_violation = authorized and revoked
        histories.append({
            "events": list(history),
            "update_committed": update_committed,
            "post_revocation_violation": post_revocation_violation,
        })
    return histories


def report() -> dict[str, object]:
    results = {}
    for policy in ("cached_admission", "recheck_at_commit"):
        histories = enumerate_histories(policy)
        results[policy] = {
            "histories": histories,
            "total_histories": len(histories),
            "post_revocation_violating_histories": sum(
                bool(h["post_revocation_violation"]) for h in histories
            ),
        }
    return {
        "kind": "abstract_three_event_exhaustive_interleavings",
        "not_an_implementation_proof": True,
        "not_a_published_baseline_comparison": True,
        "assumptions": [
            "one trusted coordinator and one participant credential generation",
            "durable_revocation_ack means revocation is durable and completed",
            "update_admission_check precedes update_commit",
            "each history is a total serialization of the three abstract events",
            "no communication faults, retries, crashes, byzantine peers or multi-leader consensus",
        ],
        "policies": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="optional path for reproducible JSON")
    args = parser.parse_args()
    result = report()
    a = result["policies"]["cached_admission"]
    b = result["policies"]["recheck_at_commit"]
    if (a["total_histories"], a["post_revocation_violating_histories"]) != (3, 1):
        raise SystemExit("unexpected cached-admission abstract counterexample count")
    if (b["total_histories"], b["post_revocation_violating_histories"]) != (3, 0):
        raise SystemExit("unexpected commit-time abstract safety count")
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
