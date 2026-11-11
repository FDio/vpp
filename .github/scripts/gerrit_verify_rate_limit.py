#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any

SHORT_WINDOW_SECONDS = 5 * 60
HOUR_WINDOW_SECONDS = 60 * 60
HISTORY_LOOKBACK_SECONDS = 6 * HOUR_WINDOW_SECONDS
MAX_HISTORY_RUNS = 500
TITLE = re.compile(r"gerrit-verify ([1-9][0-9]*)/([1-9][0-9]*)")
MARKER = re.compile(r"Admission granted admission_id=([1-9][0-9]*) at=([1-9][0-9]*)")


class CheckError(RuntimeError):
    """Accounting is unavailable; expensive validation must not start."""


def epoch(value: str) -> int:
    """Convert a timezone-aware GitHub timestamp to Unix seconds."""
    if not isinstance(value, str):
        raise CheckError("Missing timestamp in GitHub metadata")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise CheckError("GitHub timestamp has no timezone")
    return int(parsed.timestamp())


@dataclass
class Run:
    id: int
    created: int
    change: str
    patchset: str
    status: str = ""
    conclusion: str = ""
    updated: int = 0

    def active_at(self, instant: int) -> bool:
        """Infer whether this run was still active at the supplied timestamp."""
        # Cancellation can finish before the replacement inspects this run.
        return (
            self.status != "completed"
            or self.updated > instant
            or (self.conclusion == "cancelled" and self.updated == instant)
        )


@dataclass
class Admission:
    run: Run
    state: str
    admission_id: int = 0
    created: int = 0
    inherited: bool = False


def parse_runs(
    raw: list[dict[str, Any]], current_id: int, change: str, patchset: str
) -> tuple[Run, list[Run]]:
    """Return the validated current run and chronologically ordered history."""
    if not isinstance(raw, list) or len(raw) > MAX_HISTORY_RUNS:
        raise CheckError(
            f"Run history is incomplete or exceeds the {MAX_HISTORY_RUNS}-run bound"
        )
    current_item = next(
        (item for item in raw if int(item["databaseId"]) == current_id), None
    )
    if current_item is None:
        raise CheckError("The current run is missing from history")
    now = epoch(current_item["createdAt"])
    if len(raw) == MAX_HISTORY_RUNS and all(
        epoch(item["createdAt"]) > now - HOUR_WINDOW_SECONDS for item in raw
    ):
        raise CheckError(
            f"The {MAX_HISTORY_RUNS}-run history does not cover the full hourly window"
        )
    runs = []
    current = None
    for item in raw:
        created = epoch(item["createdAt"])
        run_id = int(item["databaseId"])
        if (created, run_id) > (now, current_id):
            continue
        if created < now - HISTORY_LOOKBACK_SECONDS:
            continue
        title = item["displayTitle"]
        match = TITLE.fullmatch(title)
        if created <= now - HOUR_WINDOW_SECONDS and not (match and match[1] == change):
            continue
        if match is None:
            raise CheckError(
                "Unrecognized run title; cannot safely account for history"
            )
        run = Run(run_id, created, match[1], match[2])
        runs.append(run)
        if run_id == current_id:
            current = run
    if current is None or (current.change, current.patchset) != (change, patchset):
        raise CheckError("The current run is missing or has unexpected change metadata")
    return current, sorted(runs, key=lambda run: (run.created, run.id))


def admission_for(run: Run, details: dict[str, Any]) -> Admission:
    """Classify a past run as admitted, pending, rejected, or cancelled."""
    jobs = details["jobs"]
    if not isinstance(jobs, list):
        raise CheckError("Missing GitHub jobs metadata")
    run.status = details["status"]
    run.conclusion = details["conclusion"]
    run.updated = epoch(details["updatedAt"])
    gates = [job for job in jobs if job["name"] == "Rate Limit Check"]
    if len(gates) > 1:
        raise CheckError("Ambiguous rate-limit job metadata")
    if not gates:
        if not jobs and run.status == "completed" and run.conclusion == "cancelled":
            return Admission(run, "cancelled")
        if any(
            job["name"] == "Start Verify"
            and job.get("status") in ("in_progress", "completed")
            and job["conclusion"] != "skipped"
            for job in jobs
        ):
            return Admission(run, "accepted", run.id, run.created)
        if run.status != "completed":
            return Admission(run, "pending", run.id, run.created)
        raise CheckError("Completed run has no admission or validation evidence")

    gate = gates[0]
    for step in gate["steps"]:
        if step["conclusion"] != "success" or not step["name"].startswith(
            "Admission granted "
        ):
            continue
        marker = MARKER.fullmatch(step["name"])
        if marker is None:
            raise CheckError("Invalid admission marker")
        admission_id, created = int(marker[1]), int(marker[2])
        if admission_id > run.id or created > run.created:
            raise CheckError("Admission marker refers to a future run")
        return Admission(run, "accepted", admission_id, created)

    if gate["conclusion"] == "success":
        raise CheckError("Successful rate-limit job has no admission marker")
    if gate["status"] != "completed":
        return Admission(run, "pending", run.id, run.created)
    cancelled = gate["conclusion"] == "cancelled" or (
        gate["conclusion"] == "skipped" and run.conclusion == "cancelled"
    )
    state = "cancelled" if cancelled else "rejected"
    return Admission(run, state)


def inherit(admission: Admission, previous: list[Admission]) -> bool:
    """Reuse a same-change admission active when this run was created."""
    for other in reversed(previous):
        if (
            other.state in ("accepted", "inherited")
            and other.run.change == admission.run.change
            and other.run.active_at(admission.run.created)
        ):
            admission.admission_id = other.admission_id
            admission.created = other.created
            admission.inherited = True
            return True
    return False


def decide(
    current: Run, history: list[Admission], short_limit: int, hour_limit: int
) -> tuple[bool, Admission, int, int]:
    """Reuse an admission when possible; otherwise enforce both rolling quotas."""
    accounted: list[Admission] = []
    for admission in history:
        if admission.state in ("pending", "cancelled") and inherit(
            admission, accounted
        ):
            admission.state = "inherited"
        if admission.state in ("accepted", "pending", "inherited"):
            accounted.append(admission)
    candidate = Admission(current, "pending", current.id, current.created)
    inherit(candidate, accounted)
    admissions = {(item.admission_id, item.created) for item in accounted + [candidate]}
    short_count = sum(
        created > current.created - SHORT_WINDOW_SECONDS for _, created in admissions
    )
    hour_count = sum(
        created > current.created - HOUR_WINDOW_SECONDS for _, created in admissions
    )
    allowed = candidate.inherited or (
        short_count <= short_limit and hour_count <= hour_limit
    )
    return allowed, candidate, short_count, hour_count


class Client:
    def __init__(self) -> None:
        """Set the overall deadline for GitHub and Gerrit metadata requests."""
        self.deadline = time.monotonic() + 150

    def text(self, command: list[str], timeout: float = 30) -> str:
        """Run a metadata command with bounded time and return its standard output."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise CheckError("Admission metadata lookup exceeded its time budget")
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                timeout=min(timeout, remaining),
            ).stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise CheckError(
                f"{command[0]} metadata request failed or timed out"
            ) from error

    def gh(self, *args: str) -> Any:
        """Run a GitHub CLI metadata request and decode its JSON response."""
        return json.loads(self.text(["gh", *args]))

    def owners(self, changes: set[str]) -> dict[str, str]:
        """Return change owners using one batched Gerrit query with bounded retries."""
        with tempfile.TemporaryDirectory(
            prefix="rate-limit-", dir=os.environ["RUNNER_TEMP"]
        ) as directory:
            key = Path(directory) / "key"
            hosts = Path(directory) / "known_hosts"
            key.write_text(os.environ["GERRIT_SSH_PRIVKEY"])
            hosts.write_text(os.environ["GERRIT_KNOWN_HOSTS"])
            key.chmod(0o600)
            hosts.chmod(0o600)
            query = " OR ".join(f"change:{change}" for change in sorted(changes))
            command = [
                "ssh",
                "-i",
                str(key),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={hosts}",
                "-o",
                "ConnectTimeout=10",
                "-p",
                "29418",
                f"{os.environ['GERRIT_SSH_USER']}@{os.environ['GERRIT_HOST']}",
                "gerrit",
                "query",
                "--format=JSON",
                "--no-limit",
                f"'({query})'",
            ]
            for attempt in range(3):
                try:
                    response = self.text(command, timeout=20)
                    break
                except CheckError:
                    if attempt == 2:
                        raise
                    print("Gerrit owner query failed; retrying", file=sys.stderr)
                    time.sleep(2)
            owners = {}
            for line in response.splitlines():
                item = json.loads(line)
                if "number" in item:
                    owners[str(item["number"])] = item.get("owner", {}).get("username")
            if any(
                not isinstance(owners.get(change), str) or not owners[change]
                for change in changes
            ):
                raise CheckError("Missing Gerrit owner for a change")
            return owners


def main() -> int:
    """Check the owner's quota and return 0 when admitted or 1 when blocked."""
    try:
        change = os.environ["GERRIT_CHANGE_NUMBER"]
        patchset = os.environ["GERRIT_PATCHSET_NUMBER"]
        if not re.fullmatch(r"[1-9][0-9]*", change) or not re.fullmatch(
            r"[1-9][0-9]*", patchset
        ):
            raise CheckError("Invalid Gerrit change or patchset")
        short_limit = int(os.environ["RATE_LIMIT_5MIN_COUNT"])
        hour_limit = int(os.environ["RATE_LIMIT_1H_COUNT"])
        if short_limit < 1 or hour_limit < 1:
            raise CheckError("Admission limits must be positive integers")
        current_id = int(os.environ["GITHUB_RUN_ID"])
        client = Client()
        raw = client.gh(
            "run",
            "list",
            "--workflow",
            "gerrit-verify.yml",
            "--limit",
            str(MAX_HISTORY_RUNS),
            "--json",
            "databaseId,createdAt,displayTitle",
        )
        current, runs = parse_runs(raw, current_id, change, patchset)
        owners = client.owners({run.change for run in runs})
        history = []
        for run in runs:
            if run.id != current_id and owners[run.change] == owners[change]:
                details = client.gh(
                    "run",
                    "view",
                    str(run.id),
                    "--json",
                    "jobs,status,conclusion,updatedAt",
                )
                history.append(admission_for(run, details))
        allowed, candidate, short_count, hour_count = decide(
            current, history, short_limit, hour_limit
        )
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(
                "### Submission circuit breaker\n"
                f"CI workflow admissions (including this) from {owners[change]}: "
                f"{short_count}/{short_limit} in 5 minutes; "
                f"{hour_count}/{hour_limit} in 1 hour.\n\n"
                f"Existing admission reused: {'Yes' if candidate.inherited else 'No'}.\n\n"
                "Rejected runs do not consume quota. Pending decisions reserve quota. "
                "Test failures still count. Replacements retain the original admission time.\n"
                "No queue or automatic retry; limits are provisional.\n"
            )
        if not allowed:
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write("decision=throttled\n")
            print(
                "::error::Submission rate exceeded; CI was not run. Wait for quota, then post recheck."
            )
            return 1
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(
                "decision=allowed\n"
                f"admission_id={candidate.admission_id}\nadmission_created={candidate.created}\n"
            )
        return 0
    except (CheckError, OSError, ValueError, KeyError, TypeError) as error:
        print(
            f"::error::Rate-limit check unavailable ({error}); expensive CI is blocked.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
