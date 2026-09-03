# circuit-breaker

An emergency control that lets an authorized operator stop and resume protected flows.

| Method | Purpose |
| --- | --- |
| `initialize(admin)` | Configure the administrator. |
| `is_tripped() -> bool` | Read the current breaker state. |
| `trip(admin)` | Enter the emergency-tripped state. |
| `reset(admin)` | Resume normal operation. |
