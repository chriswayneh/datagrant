# Vision (draft)

**Status:** Draft, awaiting maintainer approval (task `I-1`).

## Problem
AI developers and data scientists often need a slice of regulated data (PHI/PII) to debug, evaluate, or build a feature. Teams usually choose between standing access (too broad, never expires) and blocking the work. PAM tools grant whole systems; catalog tools (Ranger, Unity Catalog) manage standing rules.

## Vision
"PAM for data." A developer asks for exactly what they need: specific columns and rows, for a stated purpose, for N hours. datagrant checks policy, creates an expiring, masked Postgres view and role, revokes it automatically, and issues a signed JSON access receipt showing who saw what.

## Users
- **Requester:** AI/ML developer who needs data.
- **Approver / data owner:** decides policy and approves exceptions.
- **Auditor / compliance:** verifies receipts.
- **Operator:** runs datagrant and its expiry sweep.

## Success measures
- Zero standing access to regulated columns for requesters.
- Every grant expires on time, verified by receipt.
- A grant can be requested and in use within minutes.

## Out of scope for v1
SaaS, web UI, databases other than Postgres, telemetry.
