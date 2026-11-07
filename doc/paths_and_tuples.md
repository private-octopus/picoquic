# Paths and tuples

DRAFT. This note defines what "path" and "tuple" mean in picoquic,
and describes what the code currently does with them. It describes
behavior, it does not propose changes. Code comments and the API
documentation in `picoquic.h` should use the terms defined here.

## Background

Before multipath was standardized, picoquic used "path" for what
is now called a tuple: one pair of local and peer addresses. A
migration created a new path, and the old path was deleted after a
delay.

With the multipath extension, a path is a separate object
identified by a path ID, with its own packet number space. NAT
rebinding and connection migration (RFC 9000) are now handled by
adding tuples to an existing path. Some code and comments still
use the old meaning.

## Terms

- **Path** (`picoquic_path_t`): identified by `unique_path_id`.
  Without multipath there is exactly one path, `cnx->path[0]`,
  with `unique_path_id` 0.
- **Tuple** (`picoquic_tuple_t`): one local address, peer address
  and interface index used to reach the peer on a path. A path
  holds a list of tuples, starting at `path->first_tuple`.
- **Tuple 0**: the first tuple in that list, `path->first_tuple`.
  It is the tuple used by default to send packets on the path.
- **Migration**: a change of tuple 0. A migration never creates a
  path.
- **Tuple probe**: sending PATH_CHALLENGE on a tuple other than
  tuple 0 to validate it.
- Avoid "new path", "alternate path" or "old path" when the code
  means a tuple.

## Ownership of state

| Path | Tuple |
|---|---|
| path ID, status (backup, demoted, abandoned) | local address, peer address, if_index |
| packet number space and ACK state (with multipath) | challenge and response state |
| congestion control, RTT, pacing, bandwidth estimates | remote and local CID used on this tuple |
| loss counters, `nb_retransmit` | observed address, repeat count and time |
| MTU and MTU discovery | failure flag and deletion time |
| observed address sequence numbers and ack flag | |
| peer address registered in the net_id table | |

## Sending

- Data, ACK and other frames go on tuple 0 of the selected path.
  With multipath, the scheduler selects the path
  (`picoquic_select_next_path_tuple`). Without multipath, the path
  is always `path[0]`.
- Tuples other than tuple 0 only carry path-control packets
  (`picoquic_prepare_path_control_packet`): PATH_CHALLENGE,
  PATH_RESPONSE and OBSERVED_ADDRESS.
- The code treats a path as validated when its tuple 0 is
  validated (`first_tuple->challenge_verified`).

## Creating tuples

- **Locally**, with `picoquic_probe_new_tuple`. Without multipath,
  `picoquic_probe_new_path` and `picoquic_probe_new_path_ex` call
  it on `path[0]`. With multipath, `picoquic_probe_new_path_ex`
  calls it on `path[0]` only for the server preferred address.
  The client also calls it on its own when the server announces a
  preferred address. The new tuple is added at the end of the list,
  with a challenge.
- **On arrival** of a packet from an address pair that matches no
  tuple of the path (`picoquic_find_incoming_path`), if a CID is
  available for it, or the current CID can be shared as a last
  resort. The code then follows one of two cases:
  - With multipath, if the packet's destination CID differs from
    the local CID of tuple 0, it treats the change as a NAT
    rebinding. The new tuple becomes tuple 0 and is marked as
    verified. The previous tuple 0 moves to position 1 and gets a
    challenge.
  - In all other cases, including every case without multipath,
    the new tuple is added at the end of the list, with a
    challenge.

## How tuple 0 changes

1. **NAT rebinding with multipath**, as described above. The
   change happens when the packet arrives.
2. **Challenge verified.** When a PATH_RESPONSE matches the
   challenge of a tuple other than tuple 0, that tuple moves to
   position 0 (`picoquic_decode_path_response_frame`). This
   happens on both client and server. It covers explicit tuple
   migration, the server preferred address, and NAT rebinding
   without multipath. If the tuple was probed toward the preferred
   address, the remote `migration_disabled` flag is cleared.
3. **Failure.** A tuple whose challenge failed moves to the end of
   the list (`picoquic_set_tuple_challenge_failed`). The same
   happens to tuple 0 when its path exceeds 9 retransmissions
   (`picoquic_fail_path_first_tuple`). With multipath, that only
   happens if at least one other path has no retransmissions. With
   multipath, if tuple 0 is still marked failed afterwards (no
   other tuple left), the path is abandoned. Failed tuples other
   than tuple 0 are deleted after their deletion time.

What happens to path state when tuple 0 changes:

- The MTU is reset in case 2 only.
- In case 2, if the IP address changed (peer address, or local
  address when known), congestion control and RTT are reset
  (`picoquic_reset_path_congestion`), and the reset notification
  is sent to the CC algorithm. A port-only change keeps them.
- In cases 1 and 3, congestion control and RTT state are kept.
- The peer address registered in the net_id table is not updated.
  It is set only when the path is registered.
- The `picoquic_callback_path_available` callback fires each time a
  tuple's challenge is verified, with the path's `unique_path_id`.

## Packets and tuples

- Each packet records `send_path`, the path that owns its packet
  number and congestion state. It is set to NULL when the path is
  deleted. Packets do not record which tuple they were sent on.
- Every packet, including path-control packets sent on other
  tuples, is added to the path's `bytes_in_transit` and pacing.
  Its ACK or loss updates the path's RTT, congestion control and
  loss counters, unless it was sent before the path's last CC
  reset (application packet number below `cc_reset_pn`). Those
  packets are still acknowledged or repeated, but are not counted,
  and the reset sets `bytes_in_transit` to zero.
- The RTT sample from a verified challenge
  (`picoquic_update_path_rtt` with epoch -1) is only used if the
  path has no RTT estimate yet.

## Connection IDs

- Each tuple references one remote CID and one local CID. Several
  tuples may share the same remote CID. The reference count
  `nb_path_references` counts the tuples that use it.
- Retire Prior To (`picoquic_remove_not_before_cid`), CID renewal
  (`picoquic_renew_connection_id`) and
  `picoquic_dereference_stashed_cnxid` act on tuple 0 only.
- When a path is abandoned with multipath, the remote CID stash of
  the path is deleted and tuple 0's reference to it is cleared.

## Path validation frames

- Each tuple has its own challenge. Challenges are repeated up to
  `PICOQUIC_CHALLENGE_REPEAT_MAX` times, with a delay based on the
  path's retransmit timer, then the tuple is marked as failed.
- Challenges are padded to the minimum size unless the
  anti-amplification limit forbids it. The check uses the path's
  bytes sent and received. `tuple->is_nat_rebinding` would disable
  padding, but no code sets it.
- RFC 9000 (section 13.3) sends a PATH_RESPONSE once. Picoquic
  repeats a response when it matches tuple 0 of a path and that
  tuple is verified, or on the client while it has not failed
  (`picoquic_should_repeat_path_response_frame`).

## Migration disabled

- `picoquic_check_new_path_allowed` refuses new paths with multipath
  if either peer disabled migration, except toward the preferred
  address.
- `picoquic_probe_new_tuple` does not check `migration_disabled`.
- RFC 9000 (section 18.2): disable_active_migration "does not
  prohibit connection migration after a client has acted on a
  preferred_address transport parameter". Picoquic counts any
  attempt toward the preferred address as acting on it, whether
  or not it succeeds.
- A server that disabled migration treats any PATH_CHALLENGE that
  matches one of the path's tuples, including tuple 0, as a
  protocol violation. If it announced a preferred address, it
  clears its local `migration_disabled` flag instead, which allows
  migration from then on.
- Gap against the spec: before the client has acted on the
  preferred address, the server should only accept a challenge
  sent to the preferred address. The code does not check the
  destination address yet (TODO in
  `picoquic_decode_path_challenge_frame`), so a challenge on any
  tuple clears the flag.
- PATH_CHALLENGE does not mark a migration. A new path or tuple
  often starts with one, but does not have to, and a challenge can
  be sent at any time on an established path, normally on tuple 0.
  The check above is attached to the frame, so it also rejects a
  challenge on tuple 0. That is a second gap against the spec.
- Migration is detected by packets arriving on a new address pair.
  `picoquic_find_incoming_path` does not read `migration_disabled`.
  It creates the tuple and validates it as usual, so a peer that
  migrates without sending PATH_CHALLENGE is allowed to migrate.
  RFC 9000 (section 9) permits this choice: the endpoint may either
  drop such packets or proceed with path validation.
- On the client, a successful migration to the preferred address
  clears the remote `migration_disabled` flag
  (`picoquic_decode_path_response_frame`).
