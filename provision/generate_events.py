#!/usr/bin/env python3
"""Generate dummy event datasets for the RBAC test indexes.

Writes newline-delimited events to stdout for the requested dataset so
provision.sh can pipe them straight into Splunk's simple receiver endpoint.

Usage: generate_events.py alpha|beta
"""
import random
import sys
from datetime import datetime, timedelta, timezone

ALPHA_MARKER = "ALPHA-SECRET-7741"
BETA_MARKER = "BETA-SECRET-9922"

USERS = ["jsmith", "mchen", "agarcia", "tnguyen", "kpatel"]
PATHS = ["/api/orders", "/api/cart", "/checkout", "/login", "/api/products"]
STATUSES = [200, 200, 200, 201, 302, 404, 500]
AUTH_ACTIONS = ["login_success", "login_success", "login_failure", "mfa_challenge", "password_reset"]
SRC_IPS = ["10.1.2.15", "10.1.2.99", "192.168.4.20", "172.16.8.5", "203.0.113.42"]


def timestamps(n: int):
    now = datetime.now(timezone.utc)
    for i in range(n):
        yield (now - timedelta(minutes=random.randint(1, 720))).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def alpha_events():
    rng = random.Random(7741)
    random.seed(7741)
    events = []
    for ts in timestamps(50):
        user = rng.choice(USERS)
        path = rng.choice(PATHS)
        status = rng.choice(STATUSES)
        ms = rng.randint(8, 900)
        events.append(
            f'{ts} level=INFO service=webshop user={user} method=GET path={path} '
            f'status={status} response_ms={ms} trace_id=a{rng.randint(100000, 999999)}'
        )
    # Plant the marker in a handful of events so leakage is unambiguous
    for i in (3, 17, 42):
        events[i] += f" deploy_key={ALPHA_MARKER}"
    return events


def beta_events():
    rng = random.Random(9922)
    random.seed(9922)
    events = []
    for ts in timestamps(50):
        user = rng.choice(USERS)
        action = rng.choice(AUTH_ACTIONS)
        src = rng.choice(SRC_IPS)
        events.append(
            f'{ts} level=NOTICE system=idp action={action} user={user} src_ip={src} '
            f'session_id=b{rng.randint(100000, 999999)}'
        )
    for i in (5, 21, 38):
        events[i] += f" incident_ref={BETA_MARKER}"
    return events


if __name__ == "__main__":
    dataset = sys.argv[1] if len(sys.argv) > 1 else ""
    if dataset == "alpha":
        print("\n".join(alpha_events()))
    elif dataset == "beta":
        print("\n".join(beta_events()))
    else:
        sys.exit("usage: generate_events.py alpha|beta")
