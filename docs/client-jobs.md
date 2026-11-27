# The client job client

Status: client-jobs feature
Branch: `issue/client-jobs`

The client submits a command as a job and then polls the job status. The
client never applies the command to the replica view. It shows the committed
replica data and the pending job until the server reports `succeeded` and the
replica applied the commit sequence.

## Write path

A write is a job. The client sends one `CommandEnvelope` to `POST /jobs`:

```json
{
  "kind": "entity.create",
  "payload": {"id": "e1", "schemas": [], "attributes": {}},
  "idempotency_key": "client-1"
}
```

- The request uses the `auth_token` cookie.
- The request body has `Content-Type: application/json`.
- The server takes the owner from the token. A client cannot set the owner.
- The client sends no `expected_version`. The server rejects the field with
  `400` because no handler enforces it.
- The key must hold 1 to 128 bytes. The client checks the key before the
  request.
- The key is scoped to the owner. A duplicate key with the same kind and
  payload returns the stored job. A duplicate key with a different body or
  kind returns `409`.

The only client-submittable kind is `entity.create`. The payload is an
`EntityDraft` JSON value:

```json
{
  "id": "e1",
  "schemas": ["schema-id"],
  "attributes": {
    "name": {"type": "string", "value": "alice"},
    "age": {"type": "integer", "value": 30}
  }
}
```

The client does not decode the payload. It parses the JSON text and forwards
the value.

`POST /jobs` answers:

| Status | Meaning |
| --- | --- |
| `202` | The job was accepted. The body is a `JobStatusView`. |
| `400` | The body, kind, version, or key is not valid. |
| `401` | The request has no valid session. |
| `409` | The idempotency key names a different command. |
| `500` | The queue or the status view failed. |

## Poll

The client reads `GET /jobs/{id}` with the `auth_token` cookie. A `200` answer
returns a `JobStatusView`. A `404` answer means the job is absent or not
visible. A non-owner gets `404`, so the route does not show whether the job
exists. A `401` answer means the session ended.

The client stores one pending job. A poll updates the stored job only when the
id matches. A job in a terminal state does not change again.

Polling is the guaranteed status transport. The client does not implement
server-sent events in this feature.

## No optimistic write

The client does not change the replica or the query view on submit or poll.
The pending job is separate from the replica data. Until the job is
`succeeded` and the replica applied the commit, the UI shows the old committed
data.

The commit rule is:

```text
state == succeeded
and commit_seq is present
and replica_applied_seq >= commit_seq
```

A job without `commit_seq` is not committed by this rule. The write reported
no change feed position, so the client cannot prove that the replica includes
it. The caller falls back to a replica reload and compares the replica head or
generation. The `is_committed` helper stays `false` in this case.

## Rust API

`JobClient<T: Transport>` has these methods:

- `new(transport)` builds the client. It does no network work.
- `submit(kind, payload, idempotency_key)` sends `POST /jobs` and stores the
  accepted job.
- `poll(id)` sends `GET /jobs/{id}` and updates the stored job.
- `pending()` returns the stored job.
- `clear_pending()` removes the stored job.

Typed errors:

| Error | Meaning |
| --- | --- |
| `LoginRequired` | A submit or a poll answered `401`. |
| `Forbidden` | The server answered `403` on submit or poll. |
| `NotFound` | A poll `404`, or an unsafe id. |
| `Conflict` | A submit `409`. |
| `InvalidCommand` | A bad kind, payload, or key. |
| `Transport` | The request failed before an answer. |
| `InvalidBody` | The status body is not valid. |
| `UnexpectedStatus` | Any other status, such as a submit `404`. |

`UnexpectedStatus` also covers a poll `409`. These three errors use the
stable JavaScript name `request`.

## JavaScript shape

`Client::submit_job(kind, payload_json, idempotency_key)` and
`Client::poll_job(id)` return one stable JSON string:

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

The state names are `queued`, `leased`, `succeeded`, `failed`, and `dead`. A
state variant that a newer model adds becomes `unknown`; `terminal` follows
the model rule. A state string that the model does not know fails the body
parse and returns `request`.

`committed` is true only when the EAV replica is loaded and its applied
sequence covers the job commit sequence. The call does not load a replica.
When the EAV replica is not loaded, `committed` is false.

`Client::pending_job()` returns the same shape for the stored job, or `null`
when no job is stored. It does no network work.

A failed call returns one stable error name:

```json
{"error": "login_required"}
```

The error names are `login_required`, `forbidden`, `not_found`, `conflict`,
`invalid_command`, and `request`.

A `401` from submit or poll also sets the session state to login-required.
`Client::check_session()` then reports `login_required`.

## Tests

The client test suite covers:

- The POST path, body, credentials, content type, kind, payload, key, and the
  absent `expected_version`.
- A `202` submit and a `200` poll for the queued, leased, and succeeded
  states.
- A terminal job that does not change after a later poll.
- `409`, `400`, `401`, `403`, `404`, and an unexpected status.
- An empty key, a key above 128 bytes, and an invalid kind before the request.
- The commit rule for each state, a low replica head, and a missing
  `commit_seq`.
- A loaded replica and query view that do not change after a submit or a poll.
- A `401` that sets the session state to login-required.
