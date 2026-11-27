# The local client query

Status: client-query feature
Branch: `issue/client-query`

The client runs the same entity query as the server. The server builds a
filtered replica for the authenticated subject. The client opens that replica
read-only and calls the shared core search function. The client makes no
authorization decision.

## Data path

The EAV replica is an oxkv store, not the `/sync/db` file replica.

- Manifest: `GET /eav/sync/oxkv/manifest.json`
- Object: `GET /eav/sync/oxkv/objects/{object}`

The manifest is a `ReplicaManifest` with the generation, the change feed
head, and the size and SHA-256 of every object. The object key is relative to
the replica root. Examples are `manifest.json`, `ownership.json`, and
`e0/wal/...`.

The client keeps the two sources apart with `ReplicaSource`:

- `ReplicaSource::FILE`: manifest `/sync/db/manifest.json`, objects
  `/sync/db/{key}`.
- `ReplicaSource::EAV_OXKV`: manifest `/eav/sync/oxkv/manifest.json`,
  objects `/eav/sync/oxkv/objects/{key}`.

Both sources use the `auth_token` cookie. Both reject an older generation,
check every object size and SHA-256, and clear the cache on `401` or `403`.

## Read-only store

`ReplicaStorage` gives the replica object map to the oxkv reader. The map key
is relative to the replica root, so the reader opens at the empty prefix:

```rust
OxKvStore::builder()
    .with_store(storage)
    .with_prefix(ObjectPath::default())
    .build_reader()
```

The adapter returns object bytes for `get` and `get_opts`. It returns a
read-only error for `put_opts` and `delete`. `list` matches only a whole
segment prefix, so `e0` does not match `e01/sst/a.sst`.

## Entity view

The view scans the `entity:` key family one time. It reads the metadata rows
and the attribute rows:

- `entity:{id}:meta`
- `entity:{id}:attr:{name}`

The server materialized every schema default in the stored attribute rows,
so the client needs no schema. A row without a metadata row is skipped. An
id that holds a `:` is skipped. Index, outbox, timer, and reverse-reference
rows are not in the family, so the view ignores them.

The view decodes the stored attribute types: string, integer, float, boolean,
timestamp, and entity reference. It skips a JSON attribute, because a JSON
value has no exact search form. A corrupt metadata or attribute row returns
`corrupt_replica`.

## Query

`ReplicaQuery::query_attribute` resolves a page window with the core
`QueryWindow`, converts the JSON value, and calls
`rust_api_core::eav::search_by_attribute`. The result is in id order and the
cursor is the last id of the page.

A plain JSON value keeps its JSON type. A tagged value keeps the server
attribute type:

```json
{"type":"timestamp","value":1700}
{"type":"entity_ref","value":"e2"}
```

The tagged form also accepts `string`, `integer`, `float`, and `boolean`. It
rejects `json`. A JSON null, array, or untagged object is not a query value.

The view is cached by the loaded object map and its generation. A later query
reuses the view while the same object map stays stored. A new load rebuilds
the view, even when the generation does not change. A clear or a newer load
during the view open aborts the query.

Typed errors:

| Error | Meaning |
| --- | --- |
| `NotLoaded` | No replica load has succeeded, or a clear removed it. |
| `CorruptReplica` | A stored row is not valid. |
| `UnsupportedValue` | The query value has no exact search form. |
| `InvalidQuery` | The page window is not valid. |
| `Replica` | The oxkv reader failed. |

## JavaScript shape

`Client::load_eav_replica()` returns the state of the EAV replica. The shape
matches `load_replica`:

```json
{"generation":7,"head":42,"applied_seq":42,"objects":3}
```

`Client::query_replica(attribute, value_json, limit, after)` returns:

```json
{"items":["e1"],"next":"e2"}
```

`next` is `null` when no match remains. A failed query returns one name:

```json
{"error":"not_loaded"}
```

The error names are `not_loaded`, `corrupt_replica`, `unsupported_value`,
`invalid_query`, and `replica`. The shape and the names are stable.

`value_json` accepts a plain scalar or a tagged attribute value. See
[Query](#query).

## Limits

- A page size is 1 to 200. The default is 50.
- A tagged `json` query value is not supported.
- A JSON attribute is not part of the view.
- A timestamp needs the tagged `timestamp` form. A plain JSON number is an
  integer and does not match a timestamp value.
- A float compares with exact equality.
- The client keeps one replica object map in memory. It has no persistent
  storage.
- The client reads the replica that the server built. The next server build
  applies a new grant. The client-side query is not a security boundary.

## Tests

The client test suite covers:

- The source routes for the file replica and the EAV replica.
- The read-only adapter: get hit and miss, whole-segment list, read-only put
  and delete, and keys relative to the root.
- Every attribute variant, a stored default, a deleted entity, index decoys, a
  corrupt row, and a skipped JSON attribute.
- The core search vectors: a full page, a cursor, repeated rows, page limits,
  and an empty view.
- A real `oxkv::MemStorage` replica with a 40 KiB attribute that spills to a
  blob object.
- A rebuild when the replica generation changes.
