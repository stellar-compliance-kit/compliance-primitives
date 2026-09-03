# allowlist-token

A SEP-41-compatible token wrapper that gates transfers against an on-chain allowlist.

| Method | Purpose |
| --- | --- |
| `initialize(admin, token)` | Configure the administrator and underlying token. |
| `add_to_allowlist(admin, address)` | Add an address to the allowlist. |
| `remove_from_allowlist(admin, address)` | Remove an address from the allowlist. |
| `is_allowed(address) -> bool` | Read whether an address is currently allowed. |
| `transfer(from, to, amount)` | Transfer only when the compliance policy permits it. |

This is a reference interface; confirm the deployed contract configuration before invoking write methods.
