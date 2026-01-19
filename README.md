# Transfer Operations Center

Local-only mailbox routing for shared Outlook inboxes on Windows. The system monitors a shared inbox and forwards new emails to on-rotation staff, with a simple, deterministic distribution model and clear auditability.

## What It Does

- Monitors a shared Outlook inbox for new, unread emails
- Forwards each new email to an on-rotation staff member
- Distributes work deterministically across the staff list
- Keeps an audit trail of processed items
- Preserves original messages in Outlook at all times

## Workflow Overview

1) Read the shared inbox and select unread items.  
2) Apply basic exclusion rules to avoid loops and staff-only replies.  
3) Select a routing path (normal distribution or visibility-only).  
4) Forward and log the action.  
5) Move or label the original item as processed to prevent rework.  

## Forwarding Logic (High Level)

- Only unread emails are candidates
- Basic exclusion rules reduce re-routing of staff replies or loops
- Deterministic round-robin across the on-rotation list
- Optional CC visibility to a manager or group
- Processed items are moved or labeled to avoid repeat handling

## Visibility Notifications (Apps Team / Manager)

When visibility-only notification is enabled, the system can CC a manager or a group mailbox while preserving the primary assignment behavior. This is used for oversight or specialist awareness without changing the core distribution process.

Placeholder examples:
- Manager/group: `manager@local`
- Apps team: `apps-team@local`

## Unrecognized or New Senders

If an incoming sender or domain is not recognized by policy, the item is placed on hold and routed for manager visibility. This prevents accidental distribution while still ensuring the request is reviewed. Once approved, the sender/domain can be added to policy for normal routing.

## Safety & Governance

- Local-only operation; no external connectivity required
- Does not delete emails
- Append-only audit log for reviewability
- Idempotent processing via a ledger to prevent duplicates
- Corruption-safe state writes (atomic JSON)

## Dashboard

- Local Streamlit dashboard for operational visibility
- Dashboard does not talk to Outlook directly
- Dashboard writes only `settings_overrides.json`; the bot applies changes on the next tick

## Configuration Files (Canonical)

- `staff.txt`: on-rotation staff list (one address per line)
- `roster_state.json`: current rotation state
- `processed_ledger.json`: idempotency ledger of handled items
- `daily_stats.csv`: append-only activity log
- `settings_overrides.json`: optional runtime overrides applied by the bot

## Operational Notes

- Safe to stop/start; behavior is deterministic and audit-friendly
- Staff can continue using Outlook manually at any time
- Changes to `staff.txt` are picked up on the next processing tick

## Placeholder Examples

- Shared inbox: `shared-mailbox@local`
- Manager/group: `manager@local`
- Staff: `staff1@local`, `staff2@local`

## Local Tests

```bash
python -m unittest -v
```
