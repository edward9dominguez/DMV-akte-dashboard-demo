# DMV-akte-dashboard-demo — FAST Analysis (Portfolio Demo)

This repository showcases my Tableau dashboard for DMV AKTE exam analysis.  
All assets are **anonymized**: table names are generic, identifiers are **hashed**, and screenshots mask PII.

## What’s Included
- `docs/screenshots/` — static screenshots of the dashboard
- `sql/demo_query.sql` — the query powering the dashboard (scrubbed, documented)

## What the Dashboard Shows
- Average exam duration by exam type with state-average reference lines
- Filters/ Parameters for Start/End date, Office, Exam Name, Language, CDL flag, and Result
- Record-level detail for QA (counts of questions, score, completion reason)
- Secondary verification linkage (fingerprint audit → session → exam) within a configurable time window

## Data/Privacy Notes
- No raw DL numbers or IP addresses are exposed; both are hashed.
- Names, DOB, and street addresses are omitted.
- Some test types are excluded per policy/business rules (see CTE `exclude_test_ids`).

## How the SQL Works (High Level)
1. **Scope** sessions and exams to the selected date window.
2. **Exclude** certain test types (admin/instructor exams).
3. **Link** fingerprint-audit failures to sessions within *X seconds* (parameterized).
4. **Join** exams to sessions and a vault lookup (hashed driver IDs).
5. **Produce** clean facts + dimensions for Tableau, including pass/fail counters and durations.
6. (Optional) **Enrich** with non-PII DL attributes via a LEFT JOIN.

## Tech Stack
- SQL (Snowflake-like dialect), Tableau for visualization.
