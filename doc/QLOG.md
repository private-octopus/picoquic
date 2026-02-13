# How To Produce QLOG files with picoquic

Picoquic can produce [QLOG](https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/) compatible log files.

## C Interface

The simple way to enable production of `qlog` is to set `qlog` for the QUIC context,
by calling `picoquic_set_qlog()` before creating a connection.
The command is defined in `loglib/picoquic_qlog.h` as:

~~~
int picoquic_set_qlog(picoquic_quic_t* quic, char const* qlog_dir);
~~~

In this command, `qlog_dir` is the path to the directory where the qlog file will be created.

### Link on demand

Generating `qlog` files requires a sizeable amount of contant and code. The implementation uses function
pointers, that are filled during the call to `picoquic_set_qlog`. The corresponding functions
are linked (and included in the binary) if the application includes a call to `picoquic_set_qlog`.

## Command line

Qlog logging can be enabled on the command line with the `-q` parameter. `-q` expects a path to the
folder where the qlog files will be created.


Qlog logging can be used for clients and for servers.



## File name

There will be one `qlog` file per connection, with a file name derived from the
Initial Connection identifier, such as:
~~~
807c38b2c9f96095.client.qlog
~~~
The keyword `client` in the file name indicates that this is the log of the client
size of a connection. If the server also captures a qlog, the file name
will be:
~~~
807c38b2c9f96095.server.qlog
~~~

### Unique Name Option

Picoquic builds the `qlog` file names the Initial Connection ID because this
is convenient. Per QUIC specification, the Initial Connection ID is a
random string of at least 8 bytes, and the birthday paradox only kicks in
after logging billions of connections. However, collisons can still
happen, especially if the QUIC client implementation does not actually
pick random numbers.

As an option, the application can enforce the use of unique log names
by calling `picoquic_use_unique_log_names` and setting the
argument `use_unique_log_names`:
```
void picoquic_use_unique_log_names(picoquic_quic_t* quic, int use_unique_log_names)
```
In that case, the code will add a unique random number to the file name,
as in:
```
f3c22a35212f0451.3796.server.qlog
```

## Log all packets

By default, the code will only log the first 100 packets of a connection.
This is an attempt to limit the size of the log, especially on
servers that would produce a log for every incoming connection.
If the whole log is desired, the application should call:
~~~
void picoquic_set_log_level(picoquic_quic_t* quic, int log_level);
~~~
Setting the `log_level` to 1 will ensure that all packets are
logged. Setting the log level to 0 would revert back to the default behavior.

On the command line, use the argument `-L` to force a full log.

## What if it breaks

The QLOG format is based on JSON. The file contains
a preamble, then a vector of `event` records. These events are
written as they happen, adding for example a `packet_received` 
event when a packet is received, and a `packet_sent` event when a packet is sent.
If the application crashes, the file may be left with an incomplete JSON structure,
and thus be unreadable by QLOG parsers. In most cases it would suffice to manually
add the closing brackets to the file, but we cannot exclude weird cases
in which the file buffer is only partially written. In that case, the best solution
is to use a JSON recovery tool, many of which are available.
