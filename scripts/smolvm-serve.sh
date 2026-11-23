#!/usr/bin/env bash
# Shared REST helper for the remote smolvm serve path.
# Source this file from scripts/smolvm.sh or scripts/smolvm-exec.sh.
# Do not run this file as a command. The helper uses curl only.
# The helper never prints the value of SMOLVM_SERVE_TOKEN.
# CPU and memory come from SMOLVM_CPUS and SMOLVM_MEMORY_MB.
# A server with exec session endpoints runs every exec in a resumable
# session. A server without them uses the stream and buffered paths.

# Globals set by serve_init and serve_run_remote.
SERVE_CURL_CONNECT=()
SERVE_BASE=""
SERVE_MACHINE_NAME=""
SERVE_TARBALL=""
SERVE_STAGE=""
SERVE_STREAM_DIR=""
SERVE_GUEST_RC=0
SERVE_EXEC_TIMEOUT_SECS=0

# Globals for the exec session path.
# SERVE_SESSION_MODE is 1 when the server runs exec sessions.
# SERVE_SESSION_EXIT_CODE carries one guest exit code after one session.
# SERVE_SESSION_LOG names one file that also records the session output.
# SERVE_WAIT_SECS is the long-poll budget for one session read.
# SERVE_RUN_DEADLINE is the epoch second when the run must stop.
SERVE_SESSION_MODE=0
SERVE_SESSION_EXIT_CODE=""
SERVE_SESSION_LOG=""
SERVE_WAIT_SECS=55
SERVE_RUN_TIMEOUT_SECS=1800
SERVE_RUN_DEADLINE=0
# SERVE_STDIN_ONESHOT carries the local stdin for the fallback path.
SERVE_STDIN_ONESHOT=""
# SERVE_CACHE_VALUE is 1 when the create body asks for a cache disk.
# SERVE_CACHE_ATTACHED is 1 when the machine really carries the disk.
# SERVE_CACHE_ATTACHED_NAME is the base that the machine attached.
# SERVE_CACHE_SEED names the blank base that builds a missing base.
# SERVE_SYNC_TARBALL and SERVE_SYNC_STAGE hold the local-data upload.
SERVE_CACHE_VALUE=1
SERVE_CACHE_ATTACHED=0
SERVE_CACHE_ATTACHED_NAME=""
SERVE_CACHE_SEED="smolvm-seed.qcow2"
SERVE_SYNC_TARBALL=""
SERVE_SYNC_STAGE=""

# shellcheck source=scripts/smolvm-resources.sh
source "$(dirname "${BASH_SOURCE[0]}")/smolvm-resources.sh"

# Escape a string for use as a JSON string value.
# Handle the common control characters and the JSON quote characters.
json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

# Report whether the remote path is active.
serve_remote_enabled() {
  [[ -n "${SMOLVM_ADDR:-}" ]]
}

# Resolve SMOLVM_ADDR into curl connection options and a base URL.
# Accept a URL with a scheme, a bare host:port value, or a socket path.
serve_init() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is not on PATH. Install curl first." >&2
    return 1
  fi

  if ! command -v tar >/dev/null 2>&1; then
    echo "error: tar is not on PATH. Install tar first." >&2
    return 1
  fi

  local address="${SMOLVM_ADDR:-}"
  case "$address" in
  unix://*)
    SERVE_CURL_CONNECT=(--unix-socket "${address#unix://}")
    SERVE_BASE="http://localhost"
    ;;
  /*)
    SERVE_CURL_CONNECT=(--unix-socket "$address")
    SERVE_BASE="http://localhost"
    ;;
  http://* | https://*)
    SERVE_CURL_CONNECT=()
    SERVE_BASE="${address%/}"
    ;;
  *:*)
    SERVE_CURL_CONNECT=()
    SERVE_BASE="http://${address%/}"
    ;;
  *)
    echo "error: SMOLVM_ADDR has an unsupported value." >&2
    echo "error: Use a URL, a host:port value, or a socket path." >&2
    return 1
    ;;
  esac

  # Compute the server exec timeout from the curl client timeout.
  # Use the default client timeout when the value is not a positive number.
  # Keep the server timeout smaller than the client timeout.
  local client_timeout="${SMOLVM_SERVE_TIMEOUT:-120}"
  if [[ ! "$client_timeout" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
    [[ "$client_timeout" != *[1-9]* ]]; then
    client_timeout=120
  fi
  local whole_secs="${client_timeout%%.*}"
  SERVE_EXEC_TIMEOUT_SECS=$((whole_secs - 5))
  if ((SERVE_EXEC_TIMEOUT_SECS < 1)); then
    SERVE_EXEC_TIMEOUT_SECS=1
  fi
  # Compute the long-poll budget for the session reads. The server caps
  # the wait at 60 seconds. Keep the wait under the curl max-time.
  SERVE_WAIT_SECS=$((whole_secs - 5))
  if ((SERVE_WAIT_SECS < 1)); then
    SERVE_WAIT_SECS=1
  fi
  if ((SERVE_WAIT_SECS > 60)); then
    SERVE_WAIT_SECS=60
  fi
  return 0
}

# Send one request to the smolvm serve API.
# Print the response body on stdout. Print curl errors on stderr.
# Fail on an HTTP error status. Add the token header when a token is set.
serve_request() {
  local method="$1"
  local path="$2"
  shift 2

  local -a options=(
    --fail
    --silent
    --show-error
    --connect-timeout 5
    --max-time "${SMOLVM_SERVE_TIMEOUT:-120}"
    -X "$method"
  )
  if [[ -n "${SMOLVM_SERVE_TOKEN:-}" ]]; then
    options+=(-H "Authorization: Bearer ${SMOLVM_SERVE_TOKEN}")
  fi

  local url="${SERVE_BASE}${path}"
  curl "${SERVE_CURL_CONNECT[@]}" "${options[@]}" "$@" "$url"
}

# Send one request and record the answer.
# Print the HTTP status code on stdout. Write the body to the named file.
# Return the curl exit code. The call records an HTTP error status. It does
# not fail on one. A transport failure prints status 000.
serve_request_capture() {
  local method="$1"
  local path="$2"
  local body_file="$3"
  shift 3

  local -a options=(
    --silent
    --show-error
    --connect-timeout 5
    --max-time "${SMOLVM_SERVE_TIMEOUT:-120}"
    -X "$method"
    -o "$body_file"
    -w '%{http_code}'
  )
  if [[ -n "${SMOLVM_SERVE_TOKEN:-}" ]]; then
    options+=(-H "Authorization: Bearer ${SMOLVM_SERVE_TOKEN}")
  fi

  local url="${SERVE_BASE}${path}"
  curl "${SERVE_CURL_CONNECT[@]}" "${options[@]}" "$@" "$url"
}

# Report one failed serve call.
# Print the step, the HTTP status, and the message from the error body.
# Print transport advice when the server did not answer.
serve_api_error() {
  local step="$1"
  local status="$2"
  local body="$3"

  echo "error: the remote smolvm API call failed: ${step}." >&2
  if [[ "$status" =~ ^[1-5][0-9][0-9]$ ]]; then
    echo "error: the server answered HTTP ${status}." >&2
  else
    echo "error: the server did not answer. Check SMOLVM_ADDR and the network." >&2
  fi
  local message
  message="$(serve_json_string_field "$body" error)"
  if [[ -n "$message" ]]; then
    echo "error: the server reported: ${message}" >&2
  fi
}

# Send one request that must answer with a 2xx status.
# Print the body on stdout on success.
# Print the failure lines and return 1 on any other answer.
serve_request_ok() {
  local step="$1"
  local method="$2"
  local path="$3"
  shift 3

  local body_file
  body_file="$(mktemp "${TMPDIR:-/tmp}/smolvm-api.XXXXXX")" || return 1
  local status=""
  local rc=0
  status="$(serve_request_capture "$method" "$path" "$body_file" "$@")" || rc=$?
  local body=""
  if [[ -f "$body_file" ]]; then
    body="$(cat "$body_file" 2>/dev/null || true)"
  fi
  rm -f "$body_file"
  if ((rc == 0)) && [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
    printf '%s' "$body"
    return 0
  fi
  serve_api_error "$step" "$status" "$body"
  return 1
}

# Read and validate the total remote run timeout.
# The value comes from SMOLVM_SERVE_RUN_TIMEOUT in seconds. The default
# is 1800. The value must be a positive integer. The timeout bounds the
# whole remote run after the staging step.
serve_run_timeout_resolve() {
  local value="${SMOLVM_SERVE_RUN_TIMEOUT-1800}"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: SMOLVM_SERVE_RUN_TIMEOUT must be a positive integer." >&2
    return 1
  fi
  SERVE_RUN_TIMEOUT_SECS="$value"
}

# Read and validate the cache switch.
# The value comes from SMOLVM_SERVE_CACHE. The default is 1.
# The value must be 0 or 1. The value 1 asks the server for a cache
# disk that carries the installed tools between runs.
serve_cache_resolve() {
  local value="${SMOLVM_SERVE_CACHE-1}"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "error: SMOLVM_SERVE_CACHE must be 0 or 1." >&2
    return 1
  fi
  SERVE_CACHE_VALUE="$value"
}

# Read and validate the cache seed base name.
# The value comes from SMOLVM_SERVE_CACHE_SEED. The default is
# smolvm-seed.qcow2. An empty value disables the seed attempt.
# The name is a bare file name of at most 128 characters: letters,
# digits, hyphen, underscore, and one image suffix. A path separator
# or any other character stops the run.
serve_cache_seed_resolve() {
  local value="${SMOLVM_SERVE_CACHE_SEED-smolvm-seed.qcow2}"
  if [[ -z "$value" ]]; then
    SERVE_CACHE_SEED=""
    return 0
  fi
  if ((${#value} > 128)) ||
    [[ ! "$value" =~ ^[A-Za-z0-9_-]+\.(qcow2|img|raw)$ ]]; then
    echo "error: SMOLVM_SERVE_CACHE_SEED must be a bare file name with the suffix .qcow2, .img, or .raw." >&2
    echo "error: Use letters, digits, hyphens, and underscores. Do not use a path." >&2
    return 1
  fi
  SERVE_CACHE_SEED="$value"
}

# Compute the cache base name for one repository state.
# The name carries the owner token of the checkout and the key that the
# local pack cache uses. A change to mise.toml, one smol file, the pack
# build, or the init script names a new base. Base names stay immutable
# on the server.
serve_cache_base_name() {
  local repo_root="$1"
  local owner
  local key
  owner="$(smolvm_resources_owner_resolve "$repo_root" 1)" || return 1
  key="$(cd "$repo_root" && smolvm_resources_hash_lines | sha256sum | cut -d' ' -f1)" || return 1
  printf 'smolvm-ci-%s-%s.qcow2' "$owner" "$key"
}

# Build one create body.
# The cache base is optional. An empty name leaves the field out.
serve_create_body() {
  local worker="$1"
  local image="$2"
  local allow_field="$3"
  local cache_base="$4"
  local cache_field=""
  if [[ -n "$cache_base" ]]; then
    cache_field=",\"cacheDisk\":{\"base\":\"${cache_base}\",\"mountPath\":\"/cache\"}"
  fi
  printf '{"name":"%s","image":"%s","cpus":%s,"memoryMb":%s,"network":true%s%s,"cmd":["sh","-c","while true; do sleep 3600; done"]}' \
    "$(json_escape "$worker")" "$(json_escape "$image")" \
    "$SMOLVM_CPUS_VALUE" "$SMOLVM_MEMORY_MB_VALUE" "$allow_field" "$cache_field"
}

# Send one create call.
# Set SERVE_LAST_STATUS, SERVE_LAST_ANSWER, and SERVE_LAST_RC.
serve_create_attempt() {
  local body="$1"
  local body_file
  body_file="$(mktemp "${TMPDIR:-/tmp}/smolvm-api.XXXXXX")" || return 1
  SERVE_LAST_RC=0
  SERVE_LAST_STATUS="$(serve_request_capture POST /api/v1/machines "$body_file" \
    -H 'content-type: application/json' \
    -d "$body")" || SERVE_LAST_RC=$?
  SERVE_LAST_ANSWER=""
  if [[ -f "$body_file" ]]; then
    SERVE_LAST_ANSWER="$(cat "$body_file" 2>/dev/null || true)"
  fi
  rm -f "$body_file"
  return 0
}

# Stop the machine, publish its cache disk as a base, and start the
# machine again. A publish answer of 409 names a base that exists
# already. Treat that answer as success. Print one warning when the
# publish fails another way. Return 1 only when the machine did not
# restart.
serve_publish_cache_disk() {
  local worker="$1"
  local base="$2"
  local body_file
  local status=""
  local rc=0
  local answer=""

  if ! serve_request_ok "stop machine" POST "/api/v1/machines/${worker}/stop" \
    -H 'content-type: application/json' \
    -d '{}' >/dev/null; then
    echo "warning: the machine did not stop for the cache publish." >&2
    return 0
  fi

  body_file="$(mktemp "${TMPDIR:-/tmp}/smolvm-api.XXXXXX")" || return 1
  status="$(serve_request_capture POST \
    "/api/v1/machines/${worker}/cache-disk/publish" \
    "$body_file" \
    -H 'content-type: application/json' \
    -d "{\"base\":\"${base}\"}")" || rc=$?
  if [[ -f "$body_file" ]]; then
    answer="$(cat "$body_file" 2>/dev/null || true)"
  fi
  rm -f "$body_file"

  if ((rc == 0)) && [[ "$status" == "200" ]]; then
    local published_size=""
    local published_sha=""
    published_size="$(serve_json_number_field "$answer" sizeBytes)"
    published_sha="$(serve_json_string_field "$answer" sha256)"
    if [[ -n "$published_size" && -n "$published_sha" ]]; then
      echo "note: the cache base ${base} was published: ${published_size} bytes, sha256 ${published_sha}." >&2
    else
      echo "note: the cache base ${base} was published." >&2
    fi
  elif ((rc == 0)) && [[ "$status" == "409" ]]; then
    echo "note: the cache base ${base} exists already." >&2
  else
    serve_api_error "publish cache disk" "$status" "$answer"
    echo "warning: The cache base was not published. The next run provisions again." >&2
  fi

  if ! serve_request_ok "start machine" POST "/api/v1/machines/${worker}/start" \
    -H 'content-type: application/json' \
    -d '{}' >/dev/null; then
    return 1
  fi
  return 0
}

# Check the archive size before the upload.
# The serve upload endpoint accepts at most 1 GiB. Stop before the call
# when the archive is larger. The 413 handling stays for a server that
# answers the call anyway.
serve_upload_precheck() {
  local archive="$1"
  local limit=1073741824
  local size=""
  size="$(wc -c <"$archive" 2>/dev/null)" || {
    echo "error: the archive size was not measured." >&2
    return 1
  }
  size="${size//[[:space:]]/}"
  if [[ ! "$size" =~ ^[0-9]+$ ]]; then
    echo "error: the archive size was not measured." >&2
    return 1
  fi
  if ((size > limit)); then
    echo "error: the worktree archive is ${size} bytes." >&2
    echo "error: the serve upload limit is ${limit} bytes (1 GiB)." >&2
    echo "error: Make the working tree smaller and run again." >&2
    return 1
  fi
  return 0
}

# Build the allowedHosts field for the create body.
# The value comes from SMOLVM_SERVE_ALLOW_HOSTS: a comma-separated list
# of hostnames. The default is unset. An unset value keeps the create
# body unchanged. A set value adds the field to the create body.
# Print "," plus the field on stdout. Print nothing when unset.
# Stop with an error when one entry is empty after the trim.
serve_allow_hosts_field() {
  local value="${SMOLVM_SERVE_ALLOW_HOSTS:-}"
  local entry
  local trimmed
  local index
  local field=',"allowedHosts":['
  local -a hosts=()

  if [[ -z "$value" ]]; then
    return 0
  fi

  while IFS= read -r entry; do
    trimmed="${entry#"${entry%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [[ -z "$trimmed" ]]; then
      echo "error: SMOLVM_SERVE_ALLOW_HOSTS has an empty entry." >&2
      echo "error: Give a comma-separated list of hostnames." >&2
      return 1
    fi
    hosts+=("$(json_escape "$trimmed")")
  done < <(tr ',' '\n' <<<"$value")

  for index in "${!hosts[@]}"; do
    if ((index > 0)); then
      field+=','
    fi
    field+="\"${hosts[$index]}\""
  done
  field+=']'
  printf '%s' "$field"
}

# Clean up the machine, the archive, and the staging directory on exit.
# Keep the exit code that the caller produced.
serve_on_exit() {
  local rc=$?
  trap - EXIT
  if [[ -n "$SERVE_MACHINE_NAME" ]]; then
    serve_request DELETE "/api/v1/machines/${SERVE_MACHINE_NAME}" >/dev/null 2>&1 || true
    SERVE_MACHINE_NAME=""
  fi
  if [[ -n "$SERVE_TARBALL" ]]; then
    rm -f "$SERVE_TARBALL"
    SERVE_TARBALL=""
  fi
  if [[ -n "$SERVE_STAGE" ]]; then
    rm -rf -- "$SERVE_STAGE"
    SERVE_STAGE=""
  fi
  if [[ -n "$SERVE_STREAM_DIR" ]]; then
    rm -rf -- "$SERVE_STREAM_DIR"
    SERVE_STREAM_DIR=""
  fi
  if [[ -n "$SERVE_SYNC_TARBALL" ]]; then
    rm -f "$SERVE_SYNC_TARBALL"
    SERVE_SYNC_TARBALL=""
  fi
  if [[ -n "$SERVE_SYNC_STAGE" ]]; then
    rm -rf -- "$SERVE_SYNC_STAGE"
    SERVE_SYNC_STAGE=""
  fi
  exit "$rc"
}

# Install the exit trap in the caller for the machine named by the argument.
serve_install_cleanup() {
  SERVE_MACHINE_NAME="$1"
  trap serve_on_exit EXIT
}

# Read the exitCode field from an exec response body.
# Print nothing when the field is absent.
serve_exec_rc() {
  local body="$1"
  printf '%s' "$body" |
    sed -n 's/.*"exitCode"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' |
    head -n 1
}

# Decode a base64 string into the file named by the second argument.
# Try GNU base64, then BSD base64, then OpenSSL.
# Return non-zero when no decoder works.
serve_decode_b64() {
  local encoded="$1"
  local output="$2"

  if command -v base64 >/dev/null 2>&1; then
    if printf '%s' "$encoded" | base64 -d >"$output" 2>/dev/null; then
      return 0
    fi
    if printf '%s' "$encoded" | base64 -D >"$output" 2>/dev/null; then
      return 0
    fi
  fi
  if command -v openssl >/dev/null 2>&1; then
    if printf '%s' "$encoded" | openssl base64 -d -A >"$output" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# Print the byte-exact stream from an exec response.
# Map stdout to stdoutB64. Map stderr to stderrB64.
# Use the lossy parser when the response has no B64 field.
serve_print_stream() {
  local body="$1"
  local key="$2"
  local b64_key="${key}B64"
  local marker="\"${b64_key}\""
  local text
  text="${body#*"$marker"}"
  if [[ "$text" == "$body" ]]; then
    echo "warning: the exec response has no ${b64_key} field." >&2
    serve_print_stream_lossy "$body" "$key"
    return $?
  fi
  text="${text#*:}"
  text="${text#"${text%%[![:space:]]*}"}"
  if [[ "$text" != \"* ]]; then
    echo "warning: the exec response has no ${b64_key} value." >&2
    serve_print_stream_lossy "$body" "$key"
    return $?
  fi
  text="${text#\"}"

  local encoded="${text%%\"*}"
  local tmp
  if ! tmp="$(mktemp "${TMPDIR:-/tmp}/smolvm-stream.XXXXXX")"; then
    echo "error: mktemp failed. Check the temp directory." >&2
    return 1
  fi
  if ! serve_decode_b64 "$encoded" "$tmp"; then
    rm -f "$tmp"
    echo "error: no base64 decoder is on PATH." >&2
    echo "error: install base64 or openssl." >&2
    return 1
  fi

  if [[ -s "$tmp" ]]; then
    cat "$tmp"
    # Keep the newline framing from the lossy parser.
    local tail_byte
    tail_byte="$(
      tail -c 1 "$tmp"
      printf 'X'
    )"
    if [[ "$tail_byte" != $'\nX' ]]; then
      printf '\n'
    fi
  fi
  rm -f "$tmp"
  return 0
}

# Print one string field from an exec response body.
# Decode the common JSON escapes before printing the value.
# Use this parser only for responses that have no B64 field.
serve_print_stream_lossy() {
  local body="$1"
  local key="$2"
  local marker="\"${key}\""
  local text
  text="${body#*"$marker"}"
  if [[ "$text" == "$body" ]]; then
    return 0
  fi
  text="${text#*:}"
  text="${text#"${text%%[![:space:]]*}"}"
  if [[ "$text" != \"* ]]; then
    return 0
  fi
  text="${text#\"}"

  local decoded=""
  local char
  local next
  local index=0
  local length=${#text}
  while ((index < length)); do
    char="${text:index:1}"
    if [[ "$char" == '"' ]]; then
      break
    fi
    if [[ "$char" == "\\" ]] && ((index + 1 < length)); then
      next="${text:index+1:1}"
      case "$next" in
      n) decoded+=$'\n' ;;
      r) decoded+=$'\r' ;;
      t) decoded+=$'\t' ;;
      '"') decoded+='"' ;;
      "\\") decoded+="\\" ;;
      *) decoded+="$char$next" ;;
      esac
      index=$((index + 2))
      continue
    fi
    decoded+="$char"
    index=$((index + 1))
  done

  if [[ -z "$decoded" ]]; then
    return 0
  fi
  if [[ "$decoded" == *$'\n' ]]; then
    printf '%s' "$decoded"
  else
    printf '%s\n' "$decoded"
  fi
}

# Report whether a JSON object has the named field.
serve_json_has_field() {
  local body="$1"
  local key="$2"
  [[ "$body" == *"\"${key}\""* ]]
}

# Print one string field from a JSON object.
# Decode the common JSON escapes before printing the value.
# Print nothing when the field is absent or is not a string.
serve_json_string_field() {
  local body="$1"
  local key="$2"
  local marker="\"${key}\""
  local text
  text="${body#*"$marker"}"
  if [[ "$text" == "$body" ]]; then
    return 0
  fi
  text="${text#*:}"
  text="${text#"${text%%[![:space:]]*}"}"
  if [[ "$text" != \"* ]]; then
    return 0
  fi
  text="${text#\"}"

  local decoded=""
  local char
  local next
  local index=0
  local length=${#text}
  while ((index < length)); do
    char="${text:index:1}"
    if [[ "$char" == '"' ]]; then
      break
    fi
    if [[ "$char" == "\\" ]] && ((index + 1 < length)); then
      next="${text:index+1:1}"
      case "$next" in
      n) decoded+=$'\n' ;;
      r) decoded+=$'\r' ;;
      t) decoded+=$'\t' ;;
      '"') decoded+='"' ;;
      "\\") decoded+="\\" ;;
      *) decoded+="$char$next" ;;
      esac
      index=$((index + 2))
      continue
    fi
    decoded+="$char"
    index=$((index + 1))
  done
  printf '%s' "$decoded"
}

# Print one integer field from a JSON object.
# Print nothing when the field is absent or is not a number.
serve_json_number_field() {
  local body="$1"
  local key="$2"
  local marker="\"${key}\""
  local text
  text="${body#*"$marker"}"
  if [[ "$text" == "$body" ]]; then
    return 0
  fi
  text="${text#*:}"
  text="${text#"${text%%[![:space:]]*}"}"
  if [[ "$text" =~ ^([0-9]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

# Print one base64 field as byte-exact output.
# Send the bytes to the named stream: stdout or stderr.
serve_emit_stream_b64() {
  local encoded="$1"
  local destination="$2"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/smolvm-sse.XXXXXX")" || return 1
  if ! serve_decode_b64 "$encoded" "$tmp"; then
    rm -f "$tmp"
    echo "error: no base64 decoder is on PATH." >&2
    echo "error: install base64 or openssl." >&2
    return 1
  fi
  if [[ -s "$tmp" ]]; then
    if [[ "$destination" == "stderr" ]]; then
      cat "$tmp" >&2
    else
      cat "$tmp"
    fi
  fi
  rm -f "$tmp"
  return 0
}

# Warn once when a stream event carries only lossy text.
serve_stream_warn_lossy() {
  if ((SERVE_STREAM_WARNED == 0)); then
    echo "warning: the exec stream has no base64 fields. Output is lossy UTF-8." >&2
    SERVE_STREAM_WARNED=1
  fi
}

# Print the named stream file when it exists.
serve_stream_state() {
  local path="$1"
  if [[ -f "$path" ]]; then
    head -n 1 "$path"
  fi
}

# Handle one parsed SSE event.
# Forward stdout events to stdout and stderr events to stderr.
# Record the terminal event in the stream directory.
serve_stream_handle_event() {
  local event="$1"
  local data="$2"
  local stream_dir="$3"
  local kind="$event"
  local encoded=""
  local text=""
  local code=""
  local message=""

  if [[ "$data" == \{* ]]; then
    if [[ -z "$kind" || "$kind" == "message" ]]; then
      if serve_json_has_field "$data" exitCode; then
        kind="exit"
      elif serve_json_has_field "$data" message; then
        kind="error"
      elif serve_json_has_field "$data" stdoutB64 || serve_json_has_field "$data" stdout; then
        kind="stdout"
      elif serve_json_has_field "$data" stderrB64 || serve_json_has_field "$data" stderr; then
        kind="stderr"
      fi
    fi
  fi

  case "$kind" in
  stdout | stderr)
    if [[ "$data" == \{* ]]; then
      encoded="$(serve_json_string_field "$data" "${kind}B64")"
      if [[ -n "$encoded" ]]; then
        if serve_emit_stream_b64 "$encoded" "$kind"; then
          printf '1\n' >"$stream_dir/emitted"
        fi
        return 0
      fi
      text="$(serve_json_string_field "$data" "$kind")"
      if [[ -z "$text" ]]; then
        text="$(serve_json_string_field "$data" chunk)"
      fi
      if [[ -z "$text" ]]; then
        text="$(serve_json_string_field "$data" data)"
      fi
    else
      text="$data"
    fi
    if [[ -n "$text" ]]; then
      serve_stream_warn_lossy
      if [[ "$kind" == "stderr" ]]; then
        printf '%s' "$text" >&2
      else
        printf '%s' "$text"
      fi
      printf '1\n' >"$stream_dir/emitted"
    fi
    ;;
  exit)
    if [[ "$data" == \{* ]]; then
      code="$(serve_json_number_field "$data" exitCode)"
    elif [[ "$data" =~ ^[0-9]+$ ]]; then
      code="$data"
    fi
    if [[ -n "$code" ]]; then
      printf '%s\n' "$code" >"$stream_dir/exit"
      printf 'exit\n' >"$stream_dir/terminal"
    fi
    ;;
  error)
    if [[ "$data" == \{* ]]; then
      message="$(serve_json_string_field "$data" message)"
    else
      message="$data"
    fi
    if [[ -n "$message" ]]; then
      echo "error: the exec stream reported: $message" >&2
      printf '%s\n' "$message" >"$stream_dir/error"
    fi
    printf 'error\n' >"$stream_dir/terminal"
    ;;
  *)
    # Ignore unknown events and keep-alive comments.
    ;;
  esac
  return 0
}

# Parse an SSE response from stdin.
# Forward output as each frame arrives. Write stream state to the directory.
serve_parse_sse_stream() {
  local stream_dir="$1"
  local event=""
  local data=""
  local line=""
  local value=""
  SERVE_STREAM_WARNED=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ -z "$line" ]]; then
      if [[ -n "$event" || -n "$data" ]]; then
        serve_stream_handle_event "$event" "$data" "$stream_dir" || true
        event=""
        data=""
      fi
      continue
    fi
    case "$line" in
    :*) continue ;;
    event:*)
      value="${line#event:}"
      event="${value#"${value%%[![:space:]]*}"}"
      ;;
    data:*)
      value="${line#data:}"
      value="${value# }"
      if [[ -n "$data" ]]; then
        data+=$'\n'
      fi
      data+="$value"
      ;;
    *) continue ;;
    esac
  done

  if [[ -n "$event" || -n "$data" ]]; then
    serve_stream_handle_event "$event" "$data" "$stream_dir" || true
  fi
  if [[ ! -f "$stream_dir/terminal" ]]; then
    printf 'eof\n' >"$stream_dir/terminal"
  fi
}

# Run one command through the streaming exec endpoint.
# Forward guest output as the SSE events arrive.
# Set SERVE_GUEST_RC from the exit event.
# Return 2 when the buffered path should run. Return 1 on a stream failure.
serve_stream_exec() {
  local worker="$1"
  local body="$2"
  local stream_dir
  local curl_error
  local curl_rc=0
  local parser_rc=0
  local guest_rc=""
  local terminal=""
  local emitted=0

  stream_dir="$(mktemp -d "${TMPDIR:-/tmp}/smolvm-sse.XXXXXX")" || return 1
  SERVE_STREAM_DIR="$stream_dir"
  curl_error="${stream_dir}/curl.err"

  local -a options=(
    --fail
    --silent
    --show-error
    --no-buffer
    --connect-timeout 5
    --max-time "${SMOLVM_SERVE_TIMEOUT:-120}"
    -X POST
    -H 'content-type: application/json'
    -d "$body"
  )
  if [[ -n "${SMOLVM_SERVE_TOKEN:-}" ]]; then
    options+=(-H "Authorization: Bearer ${SMOLVM_SERVE_TOKEN}")
  fi

  local -a pipe_status=()
  if curl "${SERVE_CURL_CONNECT[@]}" "${options[@]}" \
    "${SERVE_BASE}/api/v1/machines/${worker}/exec/stream" \
    2>"$curl_error" | serve_parse_sse_stream "$stream_dir"; then
    pipe_status=("${PIPESTATUS[@]}")
  else
    pipe_status=("${PIPESTATUS[@]}")
  fi
  curl_rc="${pipe_status[0]}"
  parser_rc="${pipe_status[1]:-0}"

  guest_rc="$(serve_stream_state "${stream_dir}/exit")"
  terminal="$(serve_stream_state "${stream_dir}/terminal")"
  if [[ -f "${stream_dir}/emitted" ]]; then
    emitted=1
  fi

  if [[ -n "$guest_rc" ]]; then
    if ((curl_rc != 0 || parser_rc != 0)); then
      echo "warning: the exec stream ended with a transport error." >&2
    fi
    SERVE_GUEST_RC="$guest_rc"
    rm -rf -- "$stream_dir"
    SERVE_STREAM_DIR=""
    return 0
  fi

  if ((emitted == 0)); then
    echo "warning: the exec stream gave no exit code. Using the buffered exec path." >&2
    rm -rf -- "$stream_dir"
    SERVE_STREAM_DIR=""
    return 2
  fi

  echo "error: the exec stream ended before the guest command exited." >&2
  if [[ "$terminal" == "error" ]]; then
    local message
    message="$(serve_stream_state "${stream_dir}/error")"
    if [[ -n "$message" ]]; then
      echo "error: ${message}" >&2
    fi
  fi
  rm -rf -- "$stream_dir"
  SERVE_STREAM_DIR=""
  return 1
}

# Build one exec session id from the machine name and a purpose tag.
# The id matches the server rule: 8 to 64 characters of A-Z, a-z, 0-9,
# underscore, and hyphen. Choose the id before the first start. A retried
# start with the same id finds the session that the first start made.
serve_session_exec_id() {
  local worker="$1"
  local purpose="$2"
  local exec_id="${worker}-${purpose}"
  if [[ ! "$exec_id" =~ ^[A-Za-z0-9_-]{8,64}$ ]]; then
    echo "error: the exec session id is not valid: ${exec_id}" >&2
    return 1
  fi
  printf '%s' "$exec_id"
}

# Build the body for one session start.
# The wait field lets a short command finish in this one request.
# The interactive field keeps stdin open for numbered frames.
serve_session_body() {
  local exec_id="$1"
  local command="$2"
  local stdin_mode="${3:-none}"
  local body
  body="$(printf '{"execId":"%s","command":["bash","-lc","%s"],"waitSecs":%s' \
    "$exec_id" "$(json_escape "$command")" "$SERVE_WAIT_SECS")"
  if [[ "$stdin_mode" == "pipe" ]]; then
    body+=',"interactive":true'
  fi
  body+='}'
  printf '%s' "$body"
}

# Delete one exec session. Ignore the answer. The exit trap removes the
# machine and its sessions when this call fails.
serve_session_delete() {
  local worker="$1"
  local exec_id="$2"
  serve_request DELETE "/api/v1/machines/${worker}/execs/${exec_id}" \
    >/dev/null 2>&1 || true
}

# Report whether one session answer marks the session done.
serve_session_answer_done() {
  local answer="$1"
  local marker='"done"'
  local text="${answer#*"$marker"}"
  if [[ "$text" == "$answer" ]]; then
    return 1
  fi
  text="${text#*:}"
  text="${text#"${text%%[![:space:]]*}"}"
  [[ "$text" == true* ]]
}

# Emit one decoded chunk to the stream named by the destination.
# Record the chunk in the session log when one is set.
serve_session_emit_b64() {
  local encoded="$1"
  local destination="$2"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/smolvm-session.XXXXXX")" || return 1
  if ! serve_decode_b64 "$encoded" "$tmp"; then
    rm -f "$tmp"
    echo "error: no base64 decoder is on PATH." >&2
    echo "error: install base64 or openssl." >&2
    return 1
  fi
  if [[ -s "$tmp" ]]; then
    if [[ -n "$SERVE_SESSION_LOG" ]]; then
      cat "$tmp" >>"$SERVE_SESSION_LOG" 2>/dev/null || true
    fi
    if [[ "$destination" == "stderr" ]]; then
      cat "$tmp" >&2
    else
      cat "$tmp"
    fi
  fi
  rm -f "$tmp"
  return 0
}

# Forward one output chunk from a session answer.
# One chunk names its stream and carries its bytes base64-encoded.
# The bytes are exact. This path has no lossy fallback.
serve_session_print_chunk() {
  local chunk="$1"
  local stream
  local encoded
  stream="$(serve_json_string_field "$chunk" stream)"
  encoded="$(serve_json_string_field "$chunk" data)"
  if [[ "$stream" != "stdout" && "$stream" != "stderr" ]]; then
    return 0
  fi
  if [[ -z "$encoded" ]]; then
    return 0
  fi
  serve_session_emit_b64 "$encoded" "$stream" || true
}

# Print the text of the output array from one session answer.
# Print nothing when the answer has no output field.
serve_session_output_text() {
  local answer="$1"
  local marker='"output"'
  local text="${answer#*"$marker"}"
  if [[ "$text" == "$answer" ]]; then
    return 0
  fi
  text="${text#*:}"
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text#[}"
  text="${text%]}"
  printf '%s' "$text"
}

# Print one chunk per line from the output array text.
serve_session_split_chunks() {
  local output_text="$1"
  local separator='},{'
  if [[ -z "$output_text" ]]; then
    return 0
  fi
  printf '%s\n' "${output_text//"$separator"/$'\n'}"
}

# Forward the output chunks that one session answer carries.
# The chunks keep their answer order. Stdout goes to stdout and stderr
# goes to stderr.
serve_session_print_output() {
  local answer="$1"
  local chunk
  while IFS= read -r chunk; do
    [[ -n "$chunk" ]] || continue
    serve_session_print_chunk "$chunk"
  done <<<"$(serve_session_split_chunks "$(serve_session_output_text "$answer")")"
}

# Send one numbered stdin frame to an interactive session.
# A frame already applied is acknowledged and ignored. Send the same
# seq again when a try failed.
# Return 0 when the frame applied. Return 3 when the session takes no
# stdin. Return 1 on any other failure, with the error lines printed.
serve_session_send_frame() {
  local worker="$1"
  local exec_id="$2"
  local seq="$3"
  local encoded="$4"
  local eof="$5"
  local body_file
  local status=""
  local rc=0
  local failures=0
  local body

  body_file="$(mktemp "${TMPDIR:-/tmp}/smolvm-stdin.XXXXXX")" || return 1
  body="{\"seq\":${seq},\"data\":\"${encoded}\""
  if [[ "$eof" == "1" ]]; then
    body+=',"eof":true'
  fi
  body+='}'

  while :; do
    rc=0
    status="$(serve_request_capture POST \
      "/api/v1/machines/${worker}/execs/${exec_id}/stdin" \
      "$body_file" \
      -H 'content-type: application/json' \
      -d "$body")" || rc=$?
    local answer=""
    if [[ -f "$body_file" ]]; then
      answer="$(cat "$body_file" 2>/dev/null || true)"
    fi
    if ((rc == 0)) && [[ "$status" == 2* ]]; then
      applied="$(serve_json_number_field "$answer" stdinApplied)"
      rm -f "$body_file"
      if [[ -n "$applied" && "$applied" -ge "$seq" ]]; then
        return 0
      fi
    elif ((rc == 0)) && [[ "$status" == "409" ]]; then
      rm -f "$body_file"
      return 3
    elif ((rc == 0)) && [[ "$status" == "413" ]]; then
      serve_api_error "send stdin frame ${seq}" "$status" "$answer"
      rm -f "$body_file"
      return 1
    fi
    failures=$((failures + 1))
    if ((failures >= 3)); then
      serve_api_error "send stdin frame ${seq}" "$status" "$answer"
      rm -f "$body_file"
      return 1
    fi
    sleep 1
  done
}

# Read one bounded chunk of the local stdin. Print it base64-encoded.
# Print nothing at the end of the input.
serve_stdin_chunk_b64() {
  dd bs=65536 count=1 2>/dev/null | base64 | tr -d '\n'
}

# Read the whole local stdin for the fallback path.
# Stop with an error when the input is bigger than one MiB or contains a
# NUL byte. The fallback path sends one JSON string, not frames.
# Set SERVE_STDIN_ONESHOT to the data.
serve_stdin_read_oneshot() {
  local limit=1048576
  local size=""
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/smolvm-stdin.XXXXXX")" || return 1
  if ! head -c $((limit + 1)) >"$tmp" 2>/dev/null; then
    rm -f "$tmp"
    echo "error: the local stdin was not read." >&2
    return 1
  fi
  size="$(wc -c <"$tmp" 2>/dev/null)"
  size="${size//[[:space:]]/}"
  if [[ ! "$size" =~ ^[0-9]+$ ]]; then
    rm -f "$tmp"
    echo "error: the local stdin was not measured." >&2
    return 1
  fi
  if ((size > limit)); then
    rm -f "$tmp"
    echo "error: the local stdin is ${size} bytes. The fallback path sends at most ${limit} bytes." >&2
    echo "error: Use a server with the exec session endpoints." >&2
    return 1
  fi
  if ! cmp -s <(tr -d '\0' <"$tmp") "$tmp"; then
    rm -f "$tmp"
    echo "error: the local stdin contains a NUL byte. The fallback path cannot send it." >&2
    echo "error: Use a server with the exec session endpoints." >&2
    return 1
  fi
  SERVE_STDIN_ONESHOT=""
  IFS= read -r -d '' SERVE_STDIN_ONESHOT <"$tmp" || true
  rm -f "$tmp"
  return 0
}

# Run one command through an exec session.
# Start the session once with the fixed exec id. The start answer is
# the first read. Poll the session with ?after= and a long-poll wait
# until an answer reports done. Retry a failed call with the same
# arguments up to three times. Stop when the total run timeout expires.
# Stop with the gap error when the answer reports lost output.
# Send the local stdin as numbered frames when the stdin mode is pipe.
# Delete the session after done and on every failure path.
# Set SERVE_SESSION_EXIT_CODE to the guest exit code on success.
# Return 1 on any failure.
serve_session_exec() {
  local worker="$1"
  local exec_id="$2"
  local body="$3"
  local stdin_mode="${4:-none}"
  local body_file
  local answer=""
  local status=""
  local rc=0
  local cursor=0
  local next=0
  local code=""
  local exit_code=""
  local session_error=""
  local now=0
  local failures=0
  local done=0
  local frame_rc=0
  local next_seq=0
  local encoded=""
  local wait=0
  local applied=0

  SERVE_SESSION_EXIT_CODE=""

  body_file="$(mktemp "${TMPDIR:-/tmp}/smolvm-session.XXXXXX")" || return 1

  # Start the session. A retried start with the same exec id finds the
  # session that the first start made. The command does not run twice.
  while :; do
    rc=0
    status=""
    : >"$body_file"
    status="$(serve_request_capture POST "/api/v1/machines/${worker}/execs" \
      "$body_file" \
      -H 'content-type: application/json' \
      -d "$body")" || rc=$?
    if ((rc == 0)) && [[ "$status" == 2* ]]; then
      break
    fi
    failures=$((failures + 1))
    answer=""
    if [[ -f "$body_file" ]]; then
      answer="$(cat "$body_file" 2>/dev/null || true)"
    fi
    if ((failures >= 3)) || [[ "$status" == "400" || "$status" == "404" || "$status" == "409" ]]; then
      serve_api_error "start exec session ${exec_id}" "$status" "$answer"
      rm -f "$body_file"
      serve_session_delete "$worker" "$exec_id"
      return 1
    fi
    sleep 1
  done
  failures=0

  while :; do
    answer=""
    if [[ -f "$body_file" ]]; then
      answer="$(cat "$body_file" 2>/dev/null || true)"
    fi

    # The reader fell behind and the server no longer holds the output.
    if serve_json_has_field "$answer" lost; then
      serve_session_gap_error "$answer"
      rm -f "$body_file"
      serve_session_delete "$worker" "$exec_id"
      return 1
    fi

    serve_session_print_output "$answer"

    next="$(serve_json_number_field "$answer" next)"
    if [[ -n "$next" ]]; then
      cursor="$next"
    fi
    code="$(serve_json_number_field "$answer" exitCode)"
    if [[ -n "$code" ]]; then
      exit_code="$code"
    fi
    if serve_session_answer_done "$answer"; then
      done=1
      break
    fi

    now="$(date +%s)"
    if ((SERVE_RUN_DEADLINE > 0)) && ((now >= SERVE_RUN_DEADLINE)); then
      echo "error: the remote run exceeded SMOLVM_SERVE_RUN_TIMEOUT=${SERVE_RUN_TIMEOUT_SECS} seconds." >&2
      echo "error: Raise the value or make the guest command faster." >&2
      rm -f "$body_file"
      serve_session_delete "$worker" "$exec_id"
      return 1
    fi

    # Forward the local stdin as numbered frames while it lasts. Read
    # the output without a wait after each frame. The command can end
    # while the frames are still coming.
    if [[ "$stdin_mode" == "pipe" && $done == 0 ]]; then
      encoded="$(serve_stdin_chunk_b64)"
      if [[ -z "$encoded" ]]; then
        # The input ended. Close the session stdin.
        frame_rc=0
        serve_session_send_frame "$worker" "$exec_id" "$((next_seq + 1))" "" 1 || frame_rc=$?
        if ((frame_rc == 1)); then
          rm -f "$body_file"
          serve_session_delete "$worker" "$exec_id"
          return 1
        fi
        stdin_mode="sent"
      else
        next_seq=$((next_seq + 1))
        frame_rc=0
        serve_session_send_frame "$worker" "$exec_id" "$next_seq" "$encoded" 0 || frame_rc=$?
        if ((frame_rc == 1)); then
          rm -f "$body_file"
          serve_session_delete "$worker" "$exec_id"
          return 1
        fi
        if ((frame_rc == 3)); then
          echo "warning: the guest command closed its stdin early." >&2
          stdin_mode="sent"
        fi
      fi
    fi

    # Read the session. Retry the same read with the same offset after
    # one second. Give up after three failed reads in a row.
    failures=0
    while :; do
      rc=0
      status=""
      wait="$SERVE_WAIT_SECS"
      if [[ "$stdin_mode" == "pipe" ]]; then
        wait=0
      fi
      status="$(serve_request_capture GET \
        "/api/v1/machines/${worker}/execs/${exec_id}?after=${cursor}&wait=${wait}" \
        "$body_file")" || rc=$?
      if ((rc == 0)) && [[ "$status" == 2* ]]; then
        break
      fi
      failures=$((failures + 1))
      answer=""
      if [[ -f "$body_file" ]]; then
        answer="$(cat "$body_file" 2>/dev/null || true)"
      fi
      if ((failures >= 3)); then
        serve_api_error "read exec session ${exec_id}" "$status" "$answer"
        rm -f "$body_file"
        serve_session_delete "$worker" "$exec_id"
        return 1
      fi
      sleep 1
    done
    failures=0
  done

  rm -f "$body_file"
  serve_session_delete "$worker" "$exec_id"
  if [[ -z "$exit_code" ]]; then
    session_error="$(serve_json_string_field "$answer" error)"
    if [[ -n "$session_error" ]]; then
      echo "error: the exec session ended: ${session_error}" >&2
    else
      echo "error: the exec session ${exec_id} ended with no exit code." >&2
    fi
    return 1
  fi
  SERVE_SESSION_EXIT_CODE="$exit_code"
  return 0
}

# Print the error for one lost-output answer.
# The gap names the offsets that the server no longer holds.
serve_session_gap_error() {
  local answer="$1"
  local from
  local to
  from="$(serve_json_number_field "$answer" from)"
  to="$(serve_json_number_field "$answer" to)"
  echo "error: the session output was lost between offsets ${from:-0} and ${to:-0}." >&2
  echo "error: The reader fell behind. The run cannot continue." >&2
}

# Stage one local directory for the upload. Apply the symlink policy:
# - keep a relative link that stays inside the tree,
# - copy the target of a link that leaves the tree and names a regular
#   file,
# - skip the link with one warning when its target is gone or is not a
#   regular file,
# - refuse a loop and stop the run.
serve_sync_stage() {
  local source_dir="$1"
  local stage_dir="$2"
  local link
  local link_text
  local resolved
  local real
  local hops=0

  mkdir -p "$stage_dir" || return 1
  if ! cp -a "${source_dir%/}/." "$stage_dir/"; then
    echo "error: the sync directory was not copied." >&2
    return 1
  fi

  while IFS= read -r -d '' link; do
    link_text="$(readlink "$link")"
    resolved="$link"
    hops=0
    while [[ -L "$resolved" ]]; do
      link_text="$(readlink "$resolved")"
      if [[ "$link_text" == /* ]]; then
        resolved="$link_text"
      else
        resolved="$(dirname "$resolved")/$link_text"
      fi
      hops=$((hops + 1))
      if ((hops > 40)); then
        echo "error: the sync upload found a symlink loop at ${link#"$stage_dir"/}." >&2
        return 1
      fi
    done
    real="$(realpath -m -- "$resolved")"

    # A relative link that stays inside the tree is safe. Keep it when
    # its target exists. A dangling link leaves the upload to tar and
    # gets the skip branch below.
    if [[ "$link_text" != /* ]]; then
      if [[ ("$real" == "$stage_dir" || "$real" == "$stage_dir"/*) && -e "$real" ]]; then
        continue
      fi
    fi

    # The link leaves the tree or is absolute. Copy its target when the
    # target is a regular file. Skip the link otherwise.
    if [[ -f "$real" ]]; then
      rm -f "$link"
      if ! cp -- "$real" "$link"; then
        echo "error: the sync upload did not copy the target of ${link#"$stage_dir"/}." >&2
        return 1
      fi
    else
      rm -f "$link"
      echo "warning: the sync upload skipped ${link#"$stage_dir"/}: its target is missing or is not a regular file." >&2
    fi
  done < <(find "$stage_dir" -type l -print0)
  return 0
}

# Run one session exec for one purpose and stop the run on any failure.
# Record the session output in one log file when one is named.
serve_session_run() {
  local worker="$1"
  local purpose="$2"
  local command="$3"
  local stdin_mode="${4:-none}"
  local log="${5:-}"
  local exec_id

  exec_id="$(serve_session_exec_id "$worker" "$purpose")" || return 1
  if [[ -n "$log" ]]; then
    : >"$log" || return 1
    SERVE_SESSION_LOG="$log"
  fi
  if ! serve_session_exec "$worker" "$exec_id" \
    "$(serve_session_body "$exec_id" "$command" "$stdin_mode")" "$stdin_mode"; then
    SERVE_SESSION_LOG=""
    return 1
  fi
  SERVE_SESSION_LOG=""
  return 0
}

# Probe the server for the exec session API with one read-only call.
# Call the list route on the running machine. A 200 answer turns the
# session mode on for the whole run. A 404 with an empty or non-JSON
# body means the route is absent. The session mode turns off and the run
# uses the stream and buffered paths. Any other answer stops the run with
# the surfaced error.
serve_probe_sessions() {
  local worker="$1"
  local body_file
  local status=""
  local rc=0
  local body=""

  SERVE_SESSION_MODE=0
  body_file="$(mktemp "${TMPDIR:-/tmp}/smolvm-probe.XXXXXX")" || return 1
  status="$(serve_request_capture GET "/api/v1/machines/${worker}/execs" \
    "$body_file")" || rc=$?
  if [[ -f "$body_file" ]]; then
    body="$(cat "$body_file" 2>/dev/null || true)"
  fi
  rm -f "$body_file"

  if ((rc == 0)) && [[ "$status" == "200" ]]; then
    SERVE_SESSION_MODE=1
    return 0
  fi
  if ((rc == 0)) && [[ "$status" == "404" && "$body" != \{* ]]; then
    echo "warning: the server has no exec session endpoints. The run uses the stream path." >&2
    return 0
  fi
  serve_api_error "probe exec sessions" "$status" "$body"
  return 1
}

# Run the readiness exec and check its output for the marker.
# The session mode uses one exec session. The fallback mode uses the
# buffered exec endpoint. The log file records the session output.
# The purpose tag names the exec session. A second readiness check on
# the same machine needs a new tag because the server refuses an exec
# id that already ran.
serve_readiness_check() {
  local worker="$1"
  local log="$2"
  local purpose="${3:-ready}"

  if ((SERVE_SESSION_MODE == 1)); then
    if ! serve_session_run "$worker" "$purpose" "echo SMOLVM_READY" none "$log"; then
      return 1
    fi
    if ! grep -q SMOLVM_READY "$log"; then
      echo "error: the workload in the remote machine did not become ready." >&2
      return 1
    fi
    return 0
  fi

  local response
  if ! response="$(serve_request_ok "readiness check" POST \
    "/api/v1/machines/${worker}/exec" \
    -H 'content-type: application/json' \
    -d '{"command":["bash","-lc","echo SMOLVM_READY"],"timeoutSecs":'"$SERVE_EXEC_TIMEOUT_SECS"'}')"; then
    return 1
  fi
  if [[ "$response" != *SMOLVM_READY* ]]; then
    echo "error: the workload in the remote machine did not become ready." >&2
    return 1
  fi
  return 0
}

# Report whether the guest mounted the cache disk at /cache.
# The session mode uses one exec session. The fallback mode uses the
# buffered exec endpoint. Return 0 when /cache is mounted. Return 1
# when it is not mounted or the check did not run.
serve_cache_mount_check() {
  local worker="$1"
  local purpose="${2:-cache-mount}"

  if ((SERVE_SESSION_MODE == 1)); then
    if ! serve_session_run "$worker" "$purpose" "mountpoint -q /cache"; then
      return 1
    fi
    [[ "$SERVE_SESSION_EXIT_CODE" == "0" ]]
    return
  fi

  local response
  local code=""
  if ! response="$(serve_request_ok "check cache mount" POST \
    "/api/v1/machines/${worker}/exec" \
    -H 'content-type: application/json' \
    -d '{"command":["bash","-lc","mountpoint -q /cache"],"timeoutSecs":'"$SERVE_EXEC_TIMEOUT_SECS"'}')"; then
    return 1
  fi
  code="$(serve_exec_rc "$response")"
  [[ "$code" == "0" ]]
}

# Run one command in a machine on the remote server.
# Upload the live working tree as an archive before the command runs.
# Set SERVE_GUEST_RC to the guest exit code on success.
# The stdin mode names how the caller wants the local stdin handled:
# none sends nothing, auto streams a pipe through the session path.
# Return non-zero when an API call fails or a response has no exitCode.
serve_run_remote() {
  local guest_command="$1"
  local stdin_mode="${2:-none}"
  local repo_root
  local image="${SMOLVM_SERVE_IMAGE:-debian:stable-slim}"

  if ! smolvm_resources_resolve; then
    return 1
  fi
  if ! serve_init; then
    return 1
  fi
  if ! serve_run_timeout_resolve; then
    return 1
  fi
  if ! serve_cache_resolve; then
    return 1
  fi
  if ! serve_cache_seed_resolve; then
    return 1
  fi
  local allow_field=""
  if ! allow_field="$(serve_allow_hosts_field)"; then
    return 1
  fi

  echo "warning: remote mode does not use the local pack cache." >&2
  if [[ "$SERVE_CACHE_VALUE" == "1" ]]; then
    echo "warning: the init script downloads the tools when the cache base is missing." >&2
  else
    echo "warning: the init script installs the tools on every run." >&2
  fi

  repo_root="$(git rev-parse --show-toplevel)"

  local owner
  if ! owner="$(smolvm_resources_owner_resolve "$repo_root" 1)"; then
    return 1
  fi
  local worker="smolvm-remote-${owner}-$$-${RANDOM}"
  local tarball
  tarball="$(mktemp "${TMPDIR:-/tmp}/smolvm-worktree.XXXXXX.tar.gz")" || return 1

  serve_install_cleanup "$worker"
  SERVE_TARBALL="$tarball"

  local git_dir
  local common_dir
  if ! git_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --absolute-git-dir 2>/dev/null)" ||
    ! common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    echo "error: the git directories were not resolved." >&2
    return 1
  fi

  local stage
  stage="$(mktemp -d "${TMPDIR:-/tmp}/smolvm-stage.XXXXXX")" || return 1
  SERVE_STAGE="$stage"

  # Copy the working tree without the cache. Build a portable .git below.
  # The temp directory can be visible inside the repository. On this host
  # /tmp maps to the repository's .tmp directory. Without the excludes the
  # first tar would read the staging directory while the second tar writes
  # it. That loop never ends. Exclude both by their unique base names.
  local stage_name tarball_name
  stage_name="${stage##*/}"
  tarball_name="${tarball##*/}"
  if ! tar -C "$repo_root" \
    --exclude=.git --exclude=.cache \
    --exclude="*/$stage_name" --exclude="*/$tarball_name" \
    -cf - . |
    tar -C "$stage" -xf -; then
    echo "error: the working tree was not staged." >&2
    return 1
  fi

  # A worktree has a .git pointer. Copy the common git data, then overlay
  # the per-worktree files. Remove the pointer files and the worktree list.
  # A normal checkout has git_dir equal to common_dir, so one copy suffices.
  mkdir -p "$stage/.git" || return 1
  if ! cp -a "$common_dir"/. "$stage/.git"/; then
    echo "error: the common git directory was not copied." >&2
    return 1
  fi
  if [[ "$git_dir" != "$common_dir" ]]; then
    if ! cp -a "$git_dir"/. "$stage/.git"/; then
      echo "error: the worktree git directory was not copied." >&2
      return 1
    fi
  fi
  rm -f "$stage/.git/commondir" "$stage/.git/gitdir"
  rm -rf -- "$stage/.git/worktrees"

  # Check the staged git data before any API call.
  if ! git -C "$stage" rev-parse --show-toplevel >/dev/null 2>&1 ||
    ! git -C "$stage" tag --list >/dev/null 2>&1; then
    echo "error: the portable git metadata is not valid." >&2
    return 1
  fi

  if ! tar -C "$stage" -czf "$tarball" .; then
    echo "error: the working tree archive was not created." >&2
    return 1
  fi
  rm -rf -- "$stage"
  SERVE_STAGE=""

  # The serve upload endpoint accepts at most 1 GiB. Stop before the call.
  if ! serve_upload_precheck "$tarball"; then
    return 1
  fi

  # Stage the selected local directory for its own upload. The tar of
  # the worktree above never saw the sync staging directory because both
  # live in the temp directory, not in the repository.
  local sync_tarball=""
  local sync_target="${SMOLVM_SERVE_SYNC_TARGET:-/workspace}"
  if [[ -n "${SMOLVM_SERVE_SYNC_DIR:-}" ]]; then
    if [[ ! -d "${SMOLVM_SERVE_SYNC_DIR}" ]]; then
      echo "error: SMOLVM_SERVE_SYNC_DIR is not a directory: ${SMOLVM_SERVE_SYNC_DIR}" >&2
      return 1
    fi
    if [[ "$sync_target" != /* ]]; then
      echo "error: SMOLVM_SERVE_SYNC_TARGET must be an absolute guest path." >&2
      return 1
    fi
    sync_tarball="$(mktemp "${TMPDIR:-/tmp}/smolvm-sync.XXXXXX.tar.gz")" || return 1
    SERVE_SYNC_TARBALL="$sync_tarball"
    local sync_stage
    sync_stage="$(mktemp -d "${TMPDIR:-/tmp}/smolvm-sync-stage.XXXXXX")" || return 1
    SERVE_SYNC_STAGE="$sync_stage"
    if ! serve_sync_stage "${SMOLVM_SERVE_SYNC_DIR}" "$sync_stage"; then
      return 1
    fi
    if ! tar -C "$sync_stage" -czf "$sync_tarball" .; then
      echo "error: the sync directory archive was not created." >&2
      return 1
    fi
    rm -rf -- "$sync_stage"
    SERVE_SYNC_STAGE=""
    if ! serve_upload_precheck "$sync_tarball"; then
      return 1
    fi
  fi

  # The cache base name follows the repository state.
  local cache_base=""
  if [[ "$SERVE_CACHE_VALUE" == "1" ]]; then
    cache_base="$(serve_cache_base_name "$repo_root")" || return 1
  fi

  # The total backstop bounds the remote run from here. It covers the
  # upload, the init exec, and the guest command.
  local deadline_now
  deadline_now="$(date +%s)"
  SERVE_RUN_DEADLINE=$((deadline_now + SERVE_RUN_TIMEOUT_SECS))

  if ! serve_request_ok "check health" GET /health >/dev/null; then
    return 1
  fi

  # Create the machine. Ask for a cache disk when the cache is on. A
  # missing content base falls back to the seed base. The seed builds
  # the content base for the next run.
  SERVE_CACHE_ATTACHED=0
  SERVE_CACHE_ATTACHED_NAME=""
  serve_create_attempt "$(serve_create_body "$worker" "$image" "$allow_field" "$cache_base")"

  if ((SERVE_LAST_RC == 0)) && [[ "$SERVE_LAST_STATUS" == 2* ]]; then
    if [[ -n "$cache_base" ]]; then
      SERVE_CACHE_ATTACHED=1
      SERVE_CACHE_ATTACHED_NAME="$cache_base"
    fi
  elif [[ -n "$cache_base" ]] && [[ "$SERVE_LAST_STATUS" == "400" || "$SERVE_LAST_STATUS" == "422" ]]; then
    local refuse_reason
    refuse_reason="$(serve_json_string_field "$SERVE_LAST_ANSWER" error)"
    if [[ "$refuse_reason" == *"cannot stat cache base"* && -n "$SERVE_CACHE_SEED" ]]; then
      # The content base is missing. Attach the seed base and build the
      # content base from it.
      serve_request DELETE "/api/v1/machines/${worker}" >/dev/null 2>&1 || true
      echo "warning: the base ${cache_base} is missing on the server. This run attaches the seed ${SERVE_CACHE_SEED} and builds the base." >&2
      serve_create_attempt "$(serve_create_body "$worker" "$image" "$allow_field" "$SERVE_CACHE_SEED")"
      if ((SERVE_LAST_RC == 0)) && [[ "$SERVE_LAST_STATUS" == 2* ]]; then
        SERVE_CACHE_ATTACHED=1
        SERVE_CACHE_ATTACHED_NAME="$SERVE_CACHE_SEED"
      else
        # The seed did not attach. Continue without a cache disk.
        serve_request DELETE "/api/v1/machines/${worker}" >/dev/null 2>&1 || true
        local seed_reason
        seed_reason="$(serve_json_string_field "$SERVE_LAST_ANSWER" error)"
        if [[ -n "$seed_reason" ]]; then
          echo "warning: the seed base ${SERVE_CACHE_SEED} did not attach: ${seed_reason}" >&2
        else
          echo "warning: the seed base ${SERVE_CACHE_SEED} did not attach." >&2
        fi
        echo "warning: The run pays full provisioning." >&2
        if ! serve_request_ok "create machine" POST /api/v1/machines \
          -H 'content-type: application/json' \
          -d "$(serve_create_body "$worker" "$image" "$allow_field" "")" >/dev/null; then
          return 1
        fi
      fi
    elif [[ "$refuse_reason" == *"cache disks are disabled"* || -z "$SERVE_CACHE_SEED" ]]; then
      # The server has the feature off, or the seed is disabled. Name
      # the reason and continue without a cache disk.
      serve_request DELETE "/api/v1/machines/${worker}" >/dev/null 2>&1 || true
      if [[ -n "$refuse_reason" ]]; then
        echo "warning: the server refused the cache disk: ${refuse_reason}" >&2
      else
        echo "warning: the server refused the cache disk." >&2
      fi
      echo "warning: The run pays full provisioning." >&2
      if ! serve_request_ok "create machine" POST /api/v1/machines \
        -H 'content-type: application/json' \
        -d "$(serve_create_body "$worker" "$image" "$allow_field" "")" >/dev/null; then
        return 1
      fi
    else
      serve_api_error "create machine" "$SERVE_LAST_STATUS" "$SERVE_LAST_ANSWER"
      return 1
    fi
  else
    serve_api_error "create machine" "$SERVE_LAST_STATUS" "$SERVE_LAST_ANSWER"
    return 1
  fi

  if ! serve_request_ok "start machine" POST "/api/v1/machines/${worker}/start" \
    -H 'content-type: application/json' \
    -d '{}' >/dev/null; then
    return 1
  fi

  # Probe the exec session API with one read-only call. The probe decides
  # the mode once for the whole run.
  if ! serve_probe_sessions "$worker"; then
    return 1
  fi

  # Resolve the stdin mode. The session path streams a pipe as numbered
  # frames. The fallback path sends one bounded string.
  if [[ "$stdin_mode" == "auto" && -p /dev/stdin ]]; then
    if ((SERVE_SESSION_MODE == 1)); then
      stdin_mode="pipe"
    else
      if ! serve_stdin_read_oneshot; then
        return 1
      fi
    fi
  fi

  # Run the readiness exec and check its output for the marker.
  local ready_log
  ready_log="$(mktemp "${TMPDIR:-/tmp}/smolvm-ready.XXXXXX")" || return 1
  if ! serve_readiness_check "$worker" "$ready_log"; then
    rm -f "$ready_log"
    return 1
  fi
  rm -f "$ready_log"

  if ! serve_request_ok "upload working tree" PUT \
    "/api/v1/machines/${worker}/files/%2Froot%2Fsmolvm-worktree.tar.gz" \
    -H 'content-type: application/octet-stream' \
    --data-binary "@${tarball}" >/dev/null; then
    return 1
  fi

  local escaped
  local exec_body
  local guest_rc=""
  local stream_rc=0
  local sync_extract=""
  local init_started=0
  local init_ended=0

  if [[ -n "$sync_tarball" ]]; then
    # Extract the sync archive to a fresh directory and move it into
    # place. A stale link in the guest can never be written through.
    sync_extract="rm -rf /root/smolvm-sync.new && mkdir -p /root/smolvm-sync.new && tar -xzf /root/smolvm-sync.tar.gz -C /root/smolvm-sync.new && mkdir -p '$(dirname "$sync_target")' && rm -rf '${sync_target}' && mv /root/smolvm-sync.new '${sync_target}'"
    if ! serve_request_ok "upload local data" PUT \
      "/api/v1/machines/${worker}/files/%2Froot%2Fsmolvm-sync.tar.gz" \
      -H 'content-type: application/octet-stream' \
      --data-binary "@${sync_tarball}" >/dev/null; then
      return 1
    fi
    rm -f "$sync_tarball"
    SERVE_SYNC_TARBALL=""
  fi

  if ((SERVE_SESSION_MODE == 1)); then
    # The session path removes the single-request timeout cap from the
    # extract exec, the init exec, and the guest command.
    if ! serve_session_run "$worker" extract \
      "mkdir -p /workspace && tar -xzf /root/smolvm-worktree.tar.gz -C /workspace"; then
      return 1
    fi
    if [[ "$SERVE_SESSION_EXIT_CODE" != "0" ]]; then
      echo "error: the working tree was not extracted in the remote machine." >&2
      return 1
    fi

    if [[ -n "$sync_extract" ]]; then
      if ! serve_session_run "$worker" sync "$sync_extract"; then
        return 1
      fi
      if [[ "$SERVE_SESSION_EXIT_CODE" != "0" ]]; then
        echo "error: the local data was not extracted in the remote machine." >&2
        return 1
      fi
    fi

    init_started="$(date +%s)"
    if ! serve_session_run "$worker" init "bash /workspace/smol/init.sh"; then
      return 1
    fi
    init_ended="$(date +%s)"
    echo "note: the remote init ran in $((init_ended - init_started)) seconds." >&2
    if [[ "$SERVE_SESSION_EXIT_CODE" != "0" ]]; then
      echo "error: the remote machine was not provisioned." >&2
      return 1
    fi
  else
    local response
    if ! response="$(serve_request_ok "extract working tree" POST \
      "/api/v1/machines/${worker}/exec" \
      -H 'content-type: application/json' \
      -d '{"command":["bash","-lc","mkdir -p /workspace && tar -xzf /root/smolvm-worktree.tar.gz -C /workspace"],"timeoutSecs":'"$SERVE_EXEC_TIMEOUT_SECS"'}')"; then
      return 1
    fi
    local setup_rc
    setup_rc="$(serve_exec_rc "$response")"
    if [[ "$setup_rc" != "0" ]]; then
      echo "error: the working tree was not extracted in the remote machine." >&2
      return 1
    fi

    if [[ -n "$sync_extract" ]]; then
      if ! response="$(serve_request_ok "extract local data" POST \
        "/api/v1/machines/${worker}/exec" \
        -H 'content-type: application/json' \
        -d "{\"command\":[\"bash\",\"-lc\",\"$(json_escape "$sync_extract")\"],\"timeoutSecs\":${SERVE_EXEC_TIMEOUT_SECS}}")"; then
        return 1
      fi
      setup_rc="$(serve_exec_rc "$response")"
      if [[ "$setup_rc" != "0" ]]; then
        echo "error: the local data was not extracted in the remote machine." >&2
        return 1
      fi
    fi

    init_started="$(date +%s)"
    if ! response="$(serve_request_ok "provision machine" POST \
      "/api/v1/machines/${worker}/exec" \
      -H 'content-type: application/json' \
      -d '{"command":["bash","-lc","bash /workspace/smol/init.sh"],"timeoutSecs":'"$SERVE_EXEC_TIMEOUT_SECS"'}')"; then
      return 1
    fi
    init_ended="$(date +%s)"
    echo "note: the remote init ran in $((init_ended - init_started)) seconds." >&2
    serve_print_stream "$response" stdout
    serve_print_stream "$response" stderr
    local init_rc
    init_rc="$(serve_exec_rc "$response")"
    if [[ "$init_rc" != "0" ]]; then
      echo "error: the remote machine was not provisioned." >&2
      return 1
    fi
  fi

  # Check the /cache mount before the publish. A cache disk with no
  # mount cannot hold a usable base. Skip the publish in that case so
  # the client does not save an empty base.
  local cache_mounted=0
  if [[ "$SERVE_CACHE_ATTACHED" == "1" ]]; then
    if serve_cache_mount_check "$worker"; then
      cache_mounted=1
    fi
  fi

  # Publish the content-keyed base when the run attached the seed. A
  # run that attached the content-keyed base uses the published base
  # and publishes nothing.
  if [[ "$SERVE_CACHE_ATTACHED" == "1" && "$SERVE_CACHE_ATTACHED_NAME" != "$cache_base" ]]; then
    if ((cache_mounted == 0)); then
      echo "warning: The guest has no /cache mount. The client does not publish the cache base." >&2
      echo "warning: Recreate the seed base with a non-zero size. See docs/smolvm.md." >&2
    else
      if ! serve_publish_cache_disk "$worker" "$cache_base"; then
        return 1
      fi
      local ready2_log
      ready2_log="$(mktemp "${TMPDIR:-/tmp}/smolvm-ready.XXXXXX")" || return 1
      if ! serve_readiness_check "$worker" "$ready2_log" ready2; then
        rm -f "$ready2_log"
        return 1
      fi
      rm -f "$ready2_log"
    fi
  elif [[ "$SERVE_CACHE_ATTACHED" == "1" ]]; then
    if ((cache_mounted == 0)); then
      echo "warning: The guest has no /cache mount. The client does not publish the cache base." >&2
      echo "warning: The published base ${SERVE_CACHE_ATTACHED_NAME} is not usable. Delete it and run again." >&2
    else
      echo "note: the run used the published base ${cache_base}." >&2
    fi
  fi

  if ((SERVE_SESSION_MODE == 1)); then
    if ! serve_session_run "$worker" guest "$guest_command" "$stdin_mode"; then
      return 1
    fi
    guest_rc="$SERVE_SESSION_EXIT_CODE"
  else
    escaped="$(json_escape "$guest_command")"
    exec_body="{\"command\":[\"bash\",\"-lc\",\"${escaped}\"],\"timeoutSecs\":${SERVE_EXEC_TIMEOUT_SECS}"
    if [[ -n "$SERVE_STDIN_ONESHOT" ]]; then
      exec_body+=",\"stdin\":\"$(json_escape "$SERVE_STDIN_ONESHOT")\""
    fi
    exec_body+='}'

    if serve_stream_exec "$worker" "$exec_body"; then
      guest_rc="$SERVE_GUEST_RC"
    else
      stream_rc=$?
      if ((stream_rc != 2)); then
        return 1
      fi
      if ! response="$(serve_request_ok "run command" POST \
        "/api/v1/machines/${worker}/exec" \
        -H 'content-type: application/json' \
        -d "$exec_body")"; then
        return 1
      fi
      serve_print_stream "$response" stdout
      serve_print_stream "$response" stderr
      guest_rc="$(serve_exec_rc "$response")"
    fi
  fi
  if [[ -z "$guest_rc" ]]; then
    echo "error: the remote exec response has no exitCode." >&2
    return 1
  fi

  serve_request DELETE "/api/v1/machines/${worker}" >/dev/null 2>&1 || true
  SERVE_MACHINE_NAME=""
  rm -f "$tarball"
  SERVE_TARBALL=""
  # The caller reads this value after the function returns.
  # shellcheck disable=SC2034
  SERVE_GUEST_RC="$guest_rc"
  return 0
}
