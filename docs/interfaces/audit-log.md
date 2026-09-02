# audit-log

An append-only Soroban event log for compliance and governance records.

| Method | Purpose |
| --- | --- |
| `initialize(admin)` | Configure the authorized writer. |
| `record(writer, event_type, subject, data)` | Append a structured audit event. |
| `get_events(subject)` | Read events associated with an address or subject. |

Events are intended for off-chain indexing and on-chain auditability.
