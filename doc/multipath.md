# QUIC Multipath

Picoquic supports the QUIC extensions for managing multiple paths for a QUIC connection
defined in the [QUIC Multipath draft](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/).
That draft is in the final stages of processing before publication as an RFC.

## Multiple paths

The QUIC Multipath Draft defines how to create, manage and abandon "paths",
each of which is defined by a unique path identifier.

### Negotiation of the multipath capability

Endpoints negotiate the multipath capability by using the
transport parameter `initial_max_path_id`, which in
picoquic is represented by the constant `picoquic_tp_initial_max_path_id`,
and the element `initial_max_path_id` in the structures of type `picoquic_tp_t`.
Multipath support is only enabled if both endpoints publish this
transport parameters.

The endpoints negotiate a "maximum path ID", not
a "maximum number of paths". If the maximum path ID is N,
that means support for identifiers 0 to N, including N -- thus N+1 paths.
In particular, if both endpoints set the maximum path ID 0, the
connection will manage just one path, with ID 0.

### Management of the number of paths

If multipath support is negotiated, each endpoint can increment their
maximum supported path value over time by exchanging MAX_PATH_ID frames.
At any point in type, the maximum usable path ID is the minimum of
the values announced by two endpoints.

A picoquic endpoint automatically increments the maximum path ID that it
supports as paths are created and deleted, so that the number of
available paths corresponds to the local value of the
local `initial_max_path_id`.

Note: the API `picoquic_set_default_multipath_option` is mot currently
beaving correctly. Please just set the `initial_max_path_id`
parameter as discussed above.

### Connection identifiers

With the multipath extension enabled, connection identifiers are
associated with a path. When packets are received, the code examines
the incoming connection identifier to find both the connection
context and the path context within that connection.

Picoquic will automatically generate up to PICOQUIC_NB_TUPLE_TARGET
connection IDs per path, so as to facilitate path migration and
NAT rebinding -- see {{paths-and-tuples}}.

### Paths and tuples

The multipath draft maintains support for the NAT rebinding and
path migration functions defined in [RFC 9000]{https://www.rfc-editor.org/rfc/rfc9000.html}.
because of that support, a path identified by a unique path ID can
use different IP addresses and UDP port numbers over time. Each pair
of source and destination IP address and UDP port number is managed
in picoquic as a "tuple". There is always at least one tuple
defined for a path, ranked as "tuple 0". This determines the default
IP addresses and ports used by the path.

Packets may be received from the peer over a new tuple for an
existing path, identified by the unique path ID. Picoquic will create
a new tuple context for the new address and port, and manage
migration or path rebinding to the new tuple according to RFC 9000.

Picoquic itself will only create new path tuples for a path as
part of the "preferred address" feature specified in RFC 9000,
or in response to a detected NAT rebinding.

## Packet numbers and loss detection

Per the multipath draft, each path identified by a unique path identifier
is associated with a separate "packet number space". The packets are
acknowledged using a "multipath" variant of the ACK frame, which
specifies the identifier of the path for which packets are acknowledged.

### Sending acknowledgements

Because they carry a path identifier, the multipath acknowledgement
frames can be sent on any path. Picoquic will try to send these
acknowledgments on the path with the lowest latency. This results
in a shorter send/ack loop, and thus a more timely loss
detection.

### Pacing and congestion control

Pacing and congestion control are performed independently for each path.
Picoquic uses the per path congestion control to determine the
available capacity of each path.

## Path management events and API

Picoquic manages paths according to the multipath drafts, and reports the
state of each path through specialized callbacks.

### Creating new paths

The "probe new path" API attempts to validate a new path. If multipath is enabled,
the new path will come in addition to the set of existing paths; if not,
the new path when validated will replace the default path.


Like all user-level networking API, the "probe new path" API assumes that the
port numbers in the socket addresses structures are expressed in network order.

If an error occurs during a call to picoquic_probe_new_path_ex,
the function returns an error code describing the issue:

- PICOQUIC_ERROR_PATH_DUPLICATE: there is already an existing path with
  the same 4 tuple. This error only happens if the multipath extensions
  are not negotiated, because the multipath extensions allow creation of
  multiple paths with the same 4 tuple.

- PICOQUIC_ERROR_PATH_ID_BLOCKED: when using the multipath extension,
  the peers manage a max_path_id value. The code cannot create a new path
  if the path_id would exceed the limit negotiated with the peer. Applications
  encountering that error code should wait until the peer has increased the limit.
  They may want to signal the issue to the peer by queuing a PATHS_BLOCKED frame.

- PICOQUIC_ERROR_PATH_CID_BLOCKED: when using the multipath extension,
  the peers use NEW_PATH_CONNECTION_ID frame to provide CIDs associated with each
  valid path_id. The error occurs when the peer has not yet provided CIDs for the
  next path_id. Applications encountering the error should wait until the peer
  provides CID for the path. They may want to signal the issue to the peer by
  queuing a PATH_CIDS_BLOCKED frame.

- PICOQUIC_ERROR_PATH_ADDRESS_FAMILY: API error. The application is trying
  to use a four tuple with different address family for source and destination.

- PICOQUIC_ERROR_PATH_NOT_READY: API error. The application is trying to create
  paths before the connection handshake is complete. The application should wait
  until it is notified that the connection is ready.

- PICOQUIC_ERROR_PATH_LIMIT_EXCEEDED: The application is trying to create more
  simultaneous paths than allowed. It will need to close one of the existing paths
  before creating a new one.

The errors PICOQUIC_ERROR_PATH_ID_BLOCKED, PICOQUIC_ERROR_PATH_CID_BLOCKED.
PICOQUIC_ERROR_PATH_NOT_READY and PICOQUIC_ERROR_PATH_LIMIT_EXCEEDED are transient.
The application can use the `picoquic_check_new_path_allowed` API to check whether
a new path may be created. This function will return 1 if the path creation
can be attempted immediately, 0 otherwise. If the return code is 0, the stack
will issue a callback `picoquic_callback_next_path_ready` when the transient
issues are resolved and `picoquic_probe_new_path_ex` could be called
again.

### Closing paths

The "abandon path" should only be used if multipath is enabled, and if more than
one path is still available for use -- otherwise, just close the connection, or
probe a new path before abandoning this one. If the command is accepted, the
peer will be informed of the need to close the path, and the path will be
demoted after a short delay.

Calling picoquic_abandon_path() on the last path
that is not already marked for demotion returns PICOQUIC_ERROR_PATH_LAST_REMAINING
instead of demoting it, since that would eventually leave the connection with no
path to send on. The peer abandoning its last path is not affected by this check;
it simply results in the connection being closed.

### Path events and callback

Path event callbacks can be enabled by calling "picoquic_enable_path_callbacks".
This can be set as the default for new connections by calling
"picoquic_enable_path_callbacks_default". If enabled, the folling events
will be signalled by callbacks:

 - picoquic_callback_path_available: 
       A new path is available. On the client, this happens as soon as the 
       continuity has been verified. On the server, this happens when the
       continuity is verified and the client has started using the path
       (see section 8.2 of RFC 9000, path validation.)
       The same callback is used if a path was suspended, but becomes
       available again. 
 - picoquic_callback_path_suspended:
       A path that was available has been suspended. This happens for
       example if repeated transmission errors cause the scheduler to
       stop using that path for sending packets. 
 - picoquic_callback_path_deleted:
       An existing path has been deleted. The application should delete
       all references to that path.
 - picoquic_callback_path_quality_changed:
       Path parameters like RTT, data rate or packet loss rate have
       changed.

The "path" callback events use the same calling signature as the other 
callback events, but the definition of some fields changes:

 - the "stream_id" field is used to carry a "unique_path id"
 - the "bytes" and "length" fields are not used
 - the "stream_ctx" field carries the application specified "app_path_ctx"

The same "unique_path_id" is used to identify the path in the API calls.

The logical flow is that the application learns the path ID in a callback,
typically "picoquic_callback_path_available". If the application wants to
maintain path data in an app specific context, it will use a call to
"picoquic_set_app_path_ctx" to document it. The path created during
the connection setup has the unique_path_id 0.

If an error occurs, such as reference to an obsolete unique path id,
all the path management functions return -1.

The call to "refresh the connection ID" will trigger a renewal of the connection
ID used for sending packets on that path. This API is mostly used in test
programs. By default, picoquic will attempt to renew a path connection ID 
if that path resumes after a long silence: using
a new connection ID in these conditions makes correlation of old and new
connection data harder in case of NAT traversal.

## Scheduling transmission on paths

The multipath draft says very little about scheduling transmission on multiple paths.
This silence reflects the state of the art at the time of writing: we could only
find examples of the "backup" scenario, where one path is used in reserve and
only starts carrying traffic when the "active" path breaks. The draft
specifies that paths can have two states: available, or standby. If data is available,
it is only sent on one of the available path, unless no path is available,
in which case the code picks and promotes one of the standby paths.
The draft does not say how to manage transmission on multiple paths.

When asked to "prepare a packet", picoquic has to find a path that is ready to send something,
and then find what to send on that path. Find the path is done in `picoquic_select_next_path_mp`,
find what to send is done in `picoquic_prepare_packet_ready`.
The two are actually tied, but the ties are implicit:

- picoquic_select_next_path_mp checks which path could send something if given the turn,
  whether acknowledgement or data. It checks whether congestion control will allow sending of data,
  whether pacing will allow sending ACKs, which path has the lowest delays if ACKs need to be sent.
  It combines that with the status of the path, available or standby, and with the state of the path,
  nominal or experiencing losses. It tries to ensure that all paths are used.

- picoquic_prepare_packet_ready looks for what messages can be sent on the path based on pacing
  and congestion control, selects which stream has the highest priority on that path, whether
  there are control messages to send, etc.

### Reacting to packet losses

Picoquic monitors whether the data sent on path are acknowledged. If data is not
acknowledged with the transmission delay, the path is considered downgraded.
It will only be used to send upon "probe timeout". If this path was the only
path with "available" status, picoquic will start scheduling data in one of the paths
with "standby" status.

### Updating the path status

Picoquic provides the API `picoquic_set_path_status` to update the status of a
path:
```
int picoquic_set_path_status(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_path_status_enum status);
```
This has a direct impact on scheduling. 

### Path affinity

By default, stream data is sent on any of the available paths. This enables picoquic to
use the capacity of all available paths, and thus speed up transmission of large streams.
The downside is that if a stream is sent on many paths, the stream frames can be received
out of order and have to be reordered before delivering the data to the application.
This can be remedied using the "stream path affinity" API: 

```
int picoquic_set_stream_path_affinity(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t unique_path_id);
```

If the path affinity is set, the stream data will only be sent on the selected
path, unless that path is not available.

### Multipath scheduling

The application triggers data transmission by regular request to prepare a packet.
This preparation has two stages:

- First, select a path, and a tuple on that path, for which something can
   be sent.

- Then, prepare a packet for that path, selecting the frames and packets
   that need to be sent.

The path selection is guided by the availability of data and by congestion
control. A path is deemed available if it is in the available state, and
at least one of three conditions are true:

1. The path needs to send a path challenge or a path response to validate
   one of the path's tuples.

2. The path is selected for sending acknowledgements and acknowledgements
   need to be sent.

3. The path is not blocked by pacing or congestion control and has
   data to send.

This selection has to account for temporary unavailability of paths due to
loss detection. If a path is experiencing high loss and can only send
probes on time out, it should only be scheduled if when the probe timer
expires. If all available paths are marked temporary unavailable, one
of the standby paths will be scheduled.

The selection will try to visit each path, so that the usage of a path is
only gated by the path capacity, as discovered through congetsion control.
The 3rd condition, "has data to send", is affected by the affinity process.
A path has data to send if there is data available on a stream marked
with affinity on that path, if there is data available on stream not marked
with affinity to an available path, or if control frames need to be sent.

Once a path is selected, the regular preparation process will
select the frames to send on that path.


