# Use the WASM client

The client crate builds as a WebAssembly module for the browser. It checks the
session, downloads the per-user replicas, runs local entity queries, and
submits and watches jobs. This document shows how to build the module, load it
in a page, and call each method.

The client makes no authorization decision. The server filters every replica
for the authenticated subject. The client never reads the `auth_token` cookie.
The browser sends the cookie with each request.

## Build the module

The crate is a `cdylib` with `wasm-bindgen` bindings. A plain `cargo build`
creates a `.wasm` file, but the page also needs the generated JavaScript glue.
Use `wasm-pack`, or run `wasm-bindgen` on the build output.

`make wasm` runs `cargo check` for `wasm32-unknown-unknown`. It proves that the
crate compiles. It does not create a usable artifact.

### With wasm-pack

```sh
rustup target add wasm32-unknown-unknown
wasm-pack build crates/client --target web --release
```

`wasm-pack` writes a package to `crates/client/pkg`. The package holds
`rust_api_client.js`, `rust_api_client_bg.wasm`, and `package.json`.
`wasm-pack` installs a matching `wasm-bindgen` tool, so the versions agree.

### With cargo and wasm-bindgen

```sh
rustup target add wasm32-unknown-unknown
cargo build -p rust-api-client --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/rust_api_client.wasm
```

The `wasm-bindgen` command-line version must match the `wasm-bindgen` crate
version in `Cargo.lock`. A version mismatch stops the bindgen step.

Use `--target bundler` in place of `--target web` when a bundler imports the
package. The method names and the strings do not change.

## Load the module

The client uses relative request paths. Serve the page and the API from the
same origin. The browser then sends the session cookie with each request.
Cross-origin use is not supported.

```js
import init, { Client } from "./pkg/rust_api_client.js";

await init();
const client = new Client();
```

`new Client()` does no network work and reads no cookie and no storage.

Login is outside the client. Send the browser to the server login route, for
example `/auth/login`, and let the server set the `auth_token` cookie.

## Methods

Every method returns a string. The client reports a server or network failure
as a stable name. It does not throw for those failures.

### `check_session()`

Sends `GET /auth/me` with the cookie. The promise resolves to one of:

- `"authenticated"`: the session is valid.
- `"login_required"`: the server answered `401`.
- `"error"`: another status, a redirect, or a transport failure.
- `"unknown"`: no check has run.

```js
const state = await client.check_session();
if (state !== "authenticated") {
  window.location.assign("/auth/login");
}
```

### `load_replica()`

Downloads the file replica from `GET /sync/db/manifest.json` and every object
that the manifest names. It checks the size and the SHA-256 of each object. It
replaces the stored replica only after every check passes.

A success returns JSON:

```json
{"generation":7,"head":42,"applied_seq":42,"objects":3}
```

A failure returns one name: `"login_required"`, `"forbidden"`,
`"stale_generation"`, `"superseded"`, `"integrity"`, or `"request"`.

`login_required` and `forbidden` clear the cache. The other names keep the
previous cache.

### `load_eav_replica()`

Downloads the EAV oxkv replica from `GET /eav/sync/oxkv/manifest.json`, with
the same checks and the same result shape as `load_replica`. This replica
holds the entity rows. Call this method before `query_replica`.

The file replica and the EAV replica have separate caches. Load one or both.

### `query_replica(attribute, value_json, limit?, after?)`

Runs one local exact-match query on the loaded EAV replica. `attribute` is the
attribute name. `value_json` is a JSON string that holds the value. `limit` is
the page size. The default is 50 and the maximum is 200. `after` is the last
id of the previous page.

A scalar keeps its JSON type:

```js
const page = await client.query_replica("name", JSON.stringify("Ada"), 50);
```

A tagged value keeps a server attribute type:

```js
const page = await client.query_replica(
  "created_at",
  JSON.stringify({ type: "timestamp", value: 1700 }),
  50,
);
```

The tagged types are `string`, `integer`, `float`, `boolean`, `timestamp`, and
`entity_ref`. A JSON `null`, array, untagged object, or tagged `json` value is
not a valid query value.

A success returns JSON:

```json
{"items":["e1"],"next":"e2"}
```

`next` is `null` when no match remains. A failure returns JSON with one error
name:

```json
{"error":"not_loaded"}
```

The names are `not_loaded`, `corrupt_replica`, `unsupported_value`,
`invalid_query`, and `replica`. `not_loaded` means that no EAV replica is
loaded. A query does not load a replica.

A JSON attribute row is not part of the view, so the client cannot match it.

### `submit_job(kind, payload_json, idempotency_key)`

Sends `POST /jobs` with a JSON body and the cookie. Only `entity.create` is
submittable today. The server rejects any other kind with `400`.

`payload_json` is the entity draft as a JSON string. The client does not
decode the draft. It forwards the parsed value. An entity draft has this
shape:

```json
{
  "id": "customer-1",
  "schemas": ["customer"],
  "attributes": {
    "name": { "type": "string", "value": "Ada" }
  }
}
```

`idempotency_key` holds 1 to 128 bytes. Use a new key for a new command. Reuse
the same key to retry the same command.

```js
const draft = {
  id: "customer-1",
  schemas: ["customer"],
  attributes: { name: { type: "string", value: "Ada" } },
};
const job = await client.submit_job(
  "entity.create",
  JSON.stringify(draft),
  crypto.randomUUID(),
);
```

A `202` answer stores the pending job and returns JSON:

```json
{"id":"...","state":"queued","attempt":0,"error":null,
  "commit_seq":null,"terminal":false,"committed":false}
```

A failure returns JSON with one name: `login_required`, `forbidden`,
`not_found`, `conflict`, `invalid_command`, or `request`.

A submit does not change the replica or the query view.

### `poll_job(id)`

Sends `GET /jobs/{id}` with the cookie. A `200` answer updates the stored
pending job when the id matches. A terminal job does not change again. The
result shape and the error names match `submit_job`.

### `watch_job(id, on_event)`

Opens `GET /jobs/{id}/events` with the cookie. `on_event` is a JavaScript
function. The client calls it with one pending-job JSON string on each
initial, status, and terminal event. The fallback poll also calls it.

```js
const final = await client.watch_job(job.id, (event) => {
  const pending = JSON.parse(event);
  console.log(pending.state, pending.committed);
});
```

The promise resolves with the final pending-job JSON. A failure returns one
error name, the same shape and names as `poll_job`.

A stream `error` event, a closed stream, or a connection failure falls back to
polling at a fixed interval for a bounded number of polls. A terminal event
stops the watch. No poll runs after a terminal event. A callback that throws
does not stop the watch.

The browser `EventSource` API does not show the status of a refused
connection. A pre-stream `401`, `404`, or `429` therefore reaches the client as
a connection failure, and the fallback poll reports the result. The server
keeps no event history. The client does not send `Last-Event-ID`. A reconnect
receives the current status.

### `pending_job()`

Returns the stored pending job as JSON, or the text `null` when no job is
stored. It does no network work. The client stores one pending job.

## The `committed` field

`committed` is true when the job succeeded, its `commit_seq` is known, and the
loaded EAV replica applied that sequence. It is false when no EAV replica is
loaded. The client does not merge a pending command into a replica, and it
does not load a replica for this check.

## Stable names

The strings and field names are part of the API. A name, once added, stays.

- Session: `authenticated`, `login_required`, `error`, `unknown`.
- Replica load: `login_required`, `forbidden`, `stale_generation`,
  `superseded`, `integrity`, `request`.
- Query: `not_loaded`, `corrupt_replica`, `unsupported_value`,
  `invalid_query`, `replica`.
- Jobs: `login_required`, `forbidden`, `not_found`, `conflict`,
  `invalid_command`, `request`.

A job `401` sets the session state to `login_required`. The next
`check_session` then reports that state.

## Limits

- The client keeps all data in memory. A page reload clears both replicas and
  the pending job.
- The client stores one pending job. A poll or watch for another id does not
  replace that job.
- The client does not decide access. It shows only the rows that the server
  put in the replica.
- JSON-valued attribute rows are not queryable. The shared search value has no
  JSON form.
- The client supports no optimistic write. The page shows committed replica
  data and the pending job side by side.

## Related documents

- `docs/client-jobs.md` for the submit and poll contract.
- `docs/client-query.md` for the local query contract.
- `docs/client-sse.md` for the job event stream contract.
- `docs/eav-oxkv-replica.md` for the server replica contract.
