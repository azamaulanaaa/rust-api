# The client job watch

Status: client-sse feature
Branch: `issue/client-sse`
Base: `issue/client-jobs` at `11327c0`

The client watches one job over server-sent events and falls back to polling
when the stream fails. Polling is the guaranteed status transport. The stream
is an optimization. The client never changes the replica or the query view.

## Route

```text
GET /jobs/{id}/events
```

- The request carries the `auth_token` cookie.
- The browser uses same-origin credentials and does not read the cookie.
- The response has `Content-Type: text/event-stream` and
  `Cache-Control: no-store`.
- The server writes one `status` event at connect time, a `status` event on
  each change, a `: heartbeat` comment every 15 seconds, and one `terminal`
  event. A terminal event ends the stream.
- The server keeps no event history. `Last-Event-ID` is unsupported. A
  reconnect receives the current status.

The route answers before the stream starts:

| Status | Meaning |
| --- | --- |
| `400` | The id is not a UUID. |
| `401` | The request has no valid session. |
| `404` | The job is absent or not visible. |
| `429` | No stream slot is free. |

The browser `EventSource` API does not show the HTTP status of a refused
connection. A browser source reports a connection failure with no status and
the watcher polls. The poll maps `401` and `404`. A `429` is a stream failure
and falls back to polling.

## Event shapes

The `status` and `terminal` data is a `JobStatusView`:

```text
event: status
data: {"id":"0190a5c2-...","state":"queued","attempt":0}
```

The server sends the full view as one JSON line. The fields are the same as
the poll body.

The `error` data carries only a stable code. It never carries the stored view
or internal error text:

```text
event: error
data: {"code":"access_revoked"}
```

| Code | Meaning |
| --- | --- |
| `access_revoked` | The subject lost the read grant on the job. |
| `stream_unavailable` | The queue or the status view failed. |

A heartbeat is a comment:

```text
: heartbeat
```

## Rust API

`rust_api_client::jobs::sse` holds the seam and the watcher:

- `JobEvent` is one stream event: `Status`, `Terminal`, `Error`, or
  `Heartbeat`.
- `StreamErrorCode` is `AccessRevoked` or `StreamUnavailable`.
- `StreamFailure` is a connection or stream failure. It holds an optional
  HTTP status and a detail message.
- `JobEventSource::next_event` yields one event. `None` means the stream
  ended. A native test implements this trait. A browser wraps `EventSource`.
- `PollDelay::wait` waits between two fallback polls.
- `watch(jobs, id, source, delay, options, on_event)` runs the watch.
- `WatchOptions` holds the fallback interval and the poll bound. The default
  is one second between polls and 60 polls.
- `browser::BrowserEventSource` and `browser::BrowserDelay` build only for
  `wasm32`. The native graph has no browser dependency.

The watcher applies each `status` or `terminal` view through
`JobClient::apply_view`. The initial view, each status change, and the
terminal view update the stored pending job. A terminal view stops the watch
and returns the final pending job. A heartbeat is ignored.

`browser::BrowserEventSource` holds the `EventSource` wrapper. The wrapper
sets `with_credentials(true)`, so the same-origin cookie goes with the
connection.

## Fallback

The watcher drops the stream and polls `GET /jobs/{id}` when:

- the source reports a connection or stream failure;
- the source yields an `error` event with either code;
- the stream closes without a terminal event;
- a view names another job.

The fallback polls at most 60 times, one second apart. It does not busy-loop.
A zero interval skips the wait. Each poll updates the pending job. A terminal
poll stops the fallback. A watch that reaches the poll bound returns the
`request` error. The stream is dropped before the first poll, so a browser
source cannot reconnect during the fallback.

Status mapping:

| Situation | Result |
| --- | --- |
| Pre-stream `401` | `login_required` |
| Pre-stream `403` | `forbidden` |
| Pre-stream `404` | `not_found` |
| Pre-stream `429` | Poll fallback |
| Fallback `401` | `login_required` |
| Fallback `403` | `forbidden` |
| Fallback `404` | `not_found` |
| Fallback `429` | `request` |
| Poll bound reached | `request` |

A successful watch returns the final pending job. The job client stores it.
A fallback poll does not change the shape of the pending job.

## JavaScript

`Client::watch_job(id, on_event)` opens the stream and returns a promise.
`on_event` is a JavaScript function. The client calls it with one JSON string
on each initial, status, and terminal event, and on each fallback poll. The
string is the same pending-job shape as `submit_job` and `poll_job`:

```json
{
  "id": "0190a5c2-7f3a-7c2b-8e4d-0123456789ab",
  "state": "queued",
  "attempt": 0,
  "error": null,
  "commit_seq": null,
  "terminal": false,
  "committed": false
}
```

```js
const client = new Client();
const finalJson = await client.watch_job(jobId, (json) => {
  const job = JSON.parse(json);
  renderPendingJob(job);
});
```

The promise resolves with the final pending-job JSON. A failed watch resolves
with one stable error name, the same names as `poll_job`:

```json
{"error": "login_required"}
```

The error names are `login_required`, `forbidden`, `not_found`, `conflict`,
`invalid_command`, and `request`. A `401` from the fallback also sets the
session state to login-required. A fallback poll body for another job is
`request`. A callback that throws does not stop the watch; the promise still
resolves.

`Client::pending_job()` returns the final stored job after the promise
resolves. It is `null` when no job is stored.

## No optimistic write

The watch does not change the replica or the query view. The pending job is
separate from the replica data. Until the job is `succeeded` and the replica
applied the commit sequence, the UI shows the old committed data. The commit
rule is unchanged:

```text
state == succeeded
and commit_seq is present
and replica_applied_seq >= commit_seq
```

## Tests

The native tests cover:

- The initial status, a heartbeat, a status change, and the terminal event.
  The watcher applies each and stops before a poll.
- A stream failure before terminal. The fake poll returns queued then
  succeeded and the watcher resolves with the terminal state.
- `access_revoked` and `stream_unavailable`. Both fall back to polling.
- A stream that closes without a terminal event.
- A pre-stream `401`, `403`, and `404`, and a pre-stream `429`.
- A fallback `401`, `403`, `404`, and `429`.
- A terminal first event. It stops without polling.
- The poll bound and the `request` result.
- An unsafe id. It is rejected before the source is read.
- A stream view and a fallback poll for another id. Both are rejected and
  do not replace the pending job.
- A loaded replica and query view that do not change.
- The event parser, the stable stream names, and the default options.

The job client tests and the auth tests still pass.
