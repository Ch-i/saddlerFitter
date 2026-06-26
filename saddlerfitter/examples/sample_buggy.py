"""Planted-bug sample for demonstrating the saddler consensus loop.

Each function carries a deliberate, distinct defect so the propose->critique->
arbitrate pipeline has something real to find (and the critics have a stylistic
near-miss to refute).
"""
import subprocess


def run_user_cmd(cmd):
    # Shell injection: untrusted `cmd` interpolated into a shell string.
    return subprocess.run("echo " + cmd, shell=True, capture_output=True)


def dedupe(items):
    # O(n^2): membership test against a growing list.
    seen = []
    for x in items:
        if x not in seen:
            seen.append(x)
    return seen


def lookup(d, key):
    # Bare except swallows KeyboardInterrupt/SystemExit and hides real errors.
    try:
        return d[key]
    except:  # noqa: E722
        return None


def average(nums):
    # ZeroDivisionError when `nums` is empty.
    return sum(nums) / len(nums)
