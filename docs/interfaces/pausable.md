# pausable

A shared helper crate used by contracts that need an emergency pause flag. It is a library component, not a standalone deployable contract.

| Method | Purpose |
| --- | --- |
| `is_paused()` | Read the contract-local pause state. |
| `pause(admin)` | Set the pause flag after authorization by the host contract. |
| `unpause(admin)` | Clear the pause flag after authorization by the host contract. |
| `require_not_paused()` | Return the host contract’s pause error when the flag is set. |
