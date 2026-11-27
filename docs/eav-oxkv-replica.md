# The per-user EAV OxKV replica

This document is the client contract for the per-user EAV OxKV replica.
The server writes the replica when a caller runs `POST /eav/sync/replica`.
The same build still writes the JSON replica, so existing clients keep their
behavior.

## Base path

All routes need a valid session cookie or bearer token.
An anonymous request gets `401`.
A caller that has no replica gets `404`.
A caller can read only its own replica.
The object route resolves a key only through the wrapper of the caller.

| Method | Path | Body |
| --- | --- | --- |
| `POST` | `/eav/sync/replica` | Build both replicas. |
| `GET` | `/eav/sync/oxkv/manifest.json` | The wrapper manifest. |
| `GET` | `/eav/sync/oxkv/objects/{object}` | One raw OxKV object. |
| `DELETE` | `/eav/sync/replica` | Remove both replicas. |

The wrapper route sets `X-Replica-Generation` and `X-Replica-Head`.
The object route returns `application/octet-stream`.
The object route returns `404` when the wrapper does not list the key, when the
replica does not exist, or when the object is gone.
The key must match a wrapper entry exactly.
A dot segment, a made-up key, or the key of another subject returns `404`.

## Wrapper manifest

The wrapper body has the shape of `rust_api_model::wire::ReplicaManifest`:

```json
{
  "generation": 3,
  "head": 42,
  "objects": [
    {
      "key": "manifest.json",
      "size": 512,
      "sha256": "1f0c..."
    },
    {
      "key": "ownership.json",
      "size": 96,
      "sha256": "9a3d..."
    },
    {
      "key": "e000001/sst/L0/000000000.sst",
      "size": 4096,
      "sha256": "77b1..."
    }
  ]
}
```

`generation` is the build generation of the JSON replica and of the OxKV
replica.
Each build increments it, including a build at an equal head.
`head` is the change-feed sequence of the build.
The client applies the events after `head`.
The wrapper generation and head equal the JSON replica generation and head
after a successful build.
A failed wrapper publish can leave the JSON replica at a newer generation.
The server then returns `409`.
The old wrapper and the old objects stay readable.
The next successful build reconciles the wrapper to the JSON replica.

`objects` lists every raw OxKV object of the replica.
`key` is relative to the replica root.
`size` is the object size in bytes.
`sha256` is the lowercase SHA-256 hex of the object bytes.
The client must reject an object whose size or hash differs from the wrapper.

The keys are exactly the keys that the client stores in its object map.
They are not relative to a visible URL segment, so the client must not add a
generation or a subject prefix.

## Object key shape

The raw object keys are the standard OxKV layout below the replica root:

- `manifest.json` is the OxKV manifest.
- `ownership.json` is the OxKV ownership record.
- `e{epoch:06}/wal/{seq:08}.log` is one WAL file.
- `e{epoch:06}/sst/L{level}/{id:09}.sst` is one SST file.

The manifest inside the replica names these same relative paths.
The client must keep the bytes unchanged.

The entity rows inside the OxKV store use the entity-store key family:

- `entity:{id}:meta` holds the entity metadata as JSON.
- `entity:{id}:attr:{name}` holds one tagged JSON `AttributeValue`.

The store holds no index, outbox, timer, or reverse-reference row.
The store also holds one `replica:meta` row with the generation and the head.
A client query scans the `entity:` prefix.

## Server storage layout

The server stores one build under
`{db}/eav-oxkv/{sub_hash}/{generation}/{build_id}/`.
A `build.json` pointer under `{db}/eav-oxkv/{sub_hash}/{generation}/` names the
build id that the wrapper uses.
The client does not send these paths.
The object route resolves them from the wrapper and the pointer.

The unique build id keeps two builds at one generation independent.
A build cannot delete the objects of another build.
A generation that the wrapper already names returns a retryable `409`.
The OxKV replica relies on the single-writer lease for cross-process
exclusion.
The server does not add a distributed lock.
A versionless backend can return a transient `404` while the server replaces a
wrapper.
The client must retry the manifest read.
The server restores the old wrapper when the replace fails.

## Read-only client use

The client downloads the wrapper and every object, then builds a storage map
with an empty root.
Use `oxkv` only.
Do not add `oxkv-s3` or `object_store` to the client.
Those crates are server backends.
The client has no S3 client and no object-store client.

```rust
use std::sync::Arc;
use oxkv::{MemStorage, ObjectPath, OxKvStore, PutMode, Storage};

let storage = Arc::new(MemStorage::new());
for object in manifest.objects {
    let bytes = fetch_object(&object.key).await?;
    assert_eq!(bytes.len() as u64, object.size);
    assert_eq!(sha256_hex(&bytes), object.sha256);
    storage
        .put_opts(
            &ObjectPath::from(object.key.as_str()),
            bytes,
            PutMode::Create,
        )
        .await?;
}

let reader = OxKvStore::builder()
    .with_store(storage)
    .with_prefix(ObjectPath::default())
    .build_reader()
    .await?;

let meta = reader.get_bytes("entity:e1:meta").await?;
```

`build_reader` takes no epoch and never fences a writer.
It revalidates the manifest and replays a new WAL on each read.
This replica is read-only, so the client never writes through it.

## Generations and retention

A build writes every object first.
It publishes the wrapper last.
A build that fails partway leaves the old wrapper and the old objects readable.
A failed wrapper publish returns `409` and keeps the old wrapper.
A later build reconciles the wrapper to the current JSON generation and head.
A lower head never replaces a higher wrapper.
A rebuild keeps the current generation and the one before it.
It removes older generations after the new wrapper is visible.
The object route serves only the current wrapper.
The previous generation stays in storage as a safety net.
The route does not serve the previous generation.
A client that holds an old wrapper must re-read the manifest after the
wrapper changes.
A client must compare `generation` and `head` with its stored values and
restart a multi-object download when the wrapper changes.

A reset takes the subject build lock.
The reset clears the JSON replica and the OxKV replica under that lock.
The reset returns `204` when either replica existed.
The reset returns `404` only when neither replica existed.
The reset removes the wrapper, every generation, the JSON chunks, the JSON
generation, and the head.
A build that waits for the lock cannot repopulate the mirror after the reset.
The next build starts at generation `1`.
