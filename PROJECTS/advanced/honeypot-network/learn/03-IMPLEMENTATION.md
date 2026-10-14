# Implementation

## File Structure

The codebase follows standard Go project layout. Public types live in `pkg/types/`, everything else is in `internal/`. Each honeypot service gets its own package named after the Unix daemon convention (sshd, httpd, ftpd, smbd, mysqld, redisd). This avoids conflicts with Go's stdlib packages.

```
internal/
├── sshd/           # SSH (most complex: shell, filesystem, commands, keys)
│   ├── server.go   # Accept loop, auth callbacks, channel handling
│   ├── shell.go    # Interactive terminal with x/term, MOTD, command loop
│   ├── commands.go # 25+ fake command handlers
│   ├── filesystem.go # In-memory /etc/passwd, /proc/cpuinfo, etc.
│   └── hostkey.go  # Ed25519 key generation and persistence
├── httpd/          # HTTP (WordPress/phpMyAdmin fakes, scanner detection)
├── ftpd/           # FTP (PASV mode, upload capture, state machine)
├── smbd/           # SMB (NetBIOS framing, negotiate only)
├── mysqld/         # MySQL (binary wire protocol, greeting, auth, queries)
├── redisd/         # Redis (RESP protocol via tidwall/redcon)
├── event/          # Fan-out pub/sub bus + worker pool processor
├── store/          # PostgreSQL (pgxpool) + Redis streaming
├── mitre/          # ATT&CK technique index + sliding window detector
├── intel/          # IOC extraction, SSH/HTTP fingerprinting, STIX, blocklists
├── api/            # Chi REST router + WebSocket handler
├── config/         # YAML + env loading, all constants
├── session/        # Thread-safe tracker + asciicast v2 recorder
├── geo/            # MaxMind GeoIP lookup
├── ratelimit/      # Per-IP token bucket
└── ui/             # Terminal banner, colors, spinner, symbols
```

## Building the SSH Honeypot
### Architecture Overview
```
TCP Connection
↓
handleConnection  ← rate limit, session, SSH handshake
↓
ssh.ServerConfig  ← PasswordCallback + PublicKeyCallback (accept all)
↓
channel dispatch  ← session / direct-tcpip / unknown
↓
handleSessionRequest  ← pty-req / shell / exec / window-change
↓
RunShell / handleExec  ← terminal REPL or single command
↓
DispatchCommand  ← 25+ fake handlers → FakeFS
↓
session.Recorder  ← asciicast v2 capture → dashboard replay
```
The SSH service is the most complex honeypot in the codebase, spanning five files: server, shell, commands, filesystem, and host key management.

### Host Key Persistence (`hostkey.go`)

`LoadOrGenerateHostKey` loads an Ed25519 private key from disk, or generates and saves one if it does not exist. The key is written as a PKCS#8 PEM file with mode `0600`. Persisting the key means the honeypot presents a **stable fingerprint across restarts** — returning attackers see the same server identity, preventing detection based on key rotation. The directory is created with `0700` permissions if it does not already exist.

### Accept-All Authentication (`server.go`)

`Start` creates a standard TCP listener and dispatches each connection to `handleConnection` in its own goroutine. The `ssh.ServerConfig` is built with two callbacks:

- `PasswordCallback` — accepts every password, captures username + password + client version, publishes `EventLoginSuccess`
- `PublicKeyCallback` — accepts every public key, captures username + client version, publishes `EventLoginSuccess` with method `"publickey"`

Both callbacks store the username in `lastUsername` so it is available after the handshake completes. After `ssh.NewServerConn` succeeds, `tracker.SetLogin` records the authenticated username and SSH client version string against the session.

### Channel Dispatch

After the SSH handshake, the server iterates over incoming channel requests:

| Channel type | Handling |
|---|---|
| `session` | Accepted, dispatched to `handleSession` in a goroutine |
| `direct-tcpip` | Rejected with `ssh.Prohibited`, logged as `EventExploit` tagged `lateral-movement` + `mitre:T1021.004` |
| anything else | Rejected with `ssh.UnknownChannelType` |

`direct-tcpip` (SSH port forwarding) is a real attacker technique for pivoting through a compromised host — the honeypot refuses it but logs the attempt with full MITRE tagging.

### Session Request Handling (`handleSessionRequest`)

Within a `session` channel, the server handles SSH sub-requests:

| Request type | Behavior |
|---|---|
| `pty-req` | Parses terminal dimensions (cols × rows) from the payload, resizes the recorder |
| `shell` | Replies OK, calls `RunShell`, saves recording, closes channel — returns true to exit the request loop |
| `exec` | Replies OK, parses the command from the length-prefixed payload, calls `handleExec`, closes channel |
| `window-change` | Parses new dimensions, resizes recorder |
| anything else | Replies OK, ignored |

PTY dimension parsing decodes a big-endian 4-byte term name length, skips the term name, then reads two big-endian 4-byte integers for cols and rows.

### Interactive Shell (`shell.go`)

`RunShell` is the REPL loop. On entry it writes a realistic **Ubuntu 22.04 MOTD banner** with live timestamps (current time and last login 24 hours ago). It then creates an `x/term.Terminal` with an initial prompt of `username@hostname:cwd#`.

Each iteration:
1. `terminal.ReadLine()` blocks until the attacker presses Enter
2. The input is written to the `session.Recorder` as input
3. `publishCommand` emits `EventCommand` to the event bus
4. `exit` / `logout` / `quit` writes `"logout\r\n"` and returns
5. `DispatchCommand` produces output, which is CRLF-normalized and written to both the channel and the recorder
6. The prompt is updated to reflect any `cd` changes to `cmdCtx.CWD`

`handleExec` handles non-interactive command execution (e.g. `ssh host cmd`): it records the command, publishes it, runs `DispatchCommand`, writes output, and sends an `exit-status 0` request to satisfy the client.

### Fake Command Handlers (`commands.go`)

`DispatchCommand` splits input on whitespace and dispatches on the first token to 25+ handlers:

| Category | Commands |
|---|---|
| Identity | `id`, `whoami` |
| System info | `uname`, `hostname`, `uptime`, `date`, `arch`, `nproc` |
| Filesystem | `ls`, `cat`, `pwd`, `cd` |
| Processes | `ps`, `w` |
| Resources | `free`, `df` |
| Network | `ifconfig`, `ip`, `netstat` |
| Environment | `env`, `export`, `unset`, `which`, `type` |
| Download | `wget`, `curl` |
| Shell | `echo`, `history`, `exit`, `logout`, `quit` |
| Unknown | `bash: <cmd>: command not found` |

**`wget` and `curl`** are handled specially — they simulate a DNS resolution failure rather than making real outbound connections, preventing the honeypot from being used as a relay. `wget` returns `"Temporary failure in name resolution"` and `curl` returns `"Could not resolve host"`.

**`id`** returns different output based on username: `uid=0(root)` for root, `uid=1000(admin)` for any other user.

**`cd`** mutates `cmdCtx.CWD` in place so subsequent `ls`, `pwd`, and prompt updates reflect the directory change within the session.

### In-Memory Filesystem (`filesystem.go`)

`FakeFS` is a `map[string]*fileEntry` populated at construction by `NewFakeFS(hostname)`. It contains 30+ directory entries and key files:

| Path | Content |
|---|---|
| `/etc/passwd` | 16 realistic user entries including `root`, `www-data`, `sshd`, `admin` |
| `/etc/hostname` | Injected from the configured hostname |
| `/etc/os-release` | Ubuntu 22.04.4 LTS metadata |
| `/etc/ssh/sshd_config` | `PermitRootLogin yes`, `PasswordAuthentication yes` |
| `/proc/cpuinfo` | Intel Xeon Platinum 8175M, 2 cores, full flags |
| `/proc/meminfo` | 4GB RAM, 2GB swap |
| `/proc/version` | Ubuntu kernel 5.15.0-105-generic |
| `/etc/shadow` | Present but empty (mode `-rw-r-----`) |

`ListDir` builds directory listings dynamically by scanning all keys with the target path as prefix, collecting only direct children (no nested paths), sorting them alphabetically, and formatting each entry as a long-listing line with realistic timestamps — one month ago for directories, one week ago for files.

### Session Recording

Every byte of terminal I/O is captured by `session.Recorder` in **asciicast v2 format**: a JSON header line with terminal dimensions followed by event lines of `[elapsed_seconds, "o", "data"]` tuples. Input keystrokes and output bytes are recorded separately via `WriteInput` and `WriteOutput`. On shell exit, `saveRecording` writes the file to `cfg.Log.ReplayDir`. The dashboard uses xterm.js to replay these recordings with play/pause/speed controls.

### Event Publishing

Six event types are published across the SSH lifecycle:

| Event | Topic | Trigger | Tags |
|---|---|---|---|
| `EventConnect` | `TopicConnect` | TCP accept | — |
| `EventDisconnect` | `TopicDisconnect` | Connection close | — |
| `EventLoginSuccess` | `TopicAuth` | Password or pubkey callback | — |
| `EventCommand` | `TopicCommand` | Every shell command or exec | — |
| `EventExploit` | `TopicCommand` | `direct-tcpip` channel request | `lateral-movement`, `mitre:T1021.004` |

The `direct-tcpip` exploit event is published to `TopicCommand` rather than `TopicExploit` — it uses `EventExploit` as the event type but shares the command topic so it appears in the event feed alongside other session activity.

## Building the MySQL Honeypot
### Architecture Overview
```
TCP Connection
 ↓
handleConnection  ← rate limit, session, atomic connID
 ↓
buildGreeting     ← send Server Greeting (protocol v10)
↓
readPacket        ← receive auth packet, extract username
↓
publishAuth       ← always accept, send OK
↓
command loop      ← COM_QUERY / COM_PING / COM_QUIT
↓
handleQuery       ← pattern match, writeResultSet
```

### Packet Framing (`handler.go`)

MySQL uses a binary wire protocol where every packet has a 4-byte header: 3 bytes for payload length in little-endian and 1 byte for the sequence number. `writePacket` and `readPacket` handle this framing for all messages in both directions. Packets larger than 1MB are rejected to prevent memory exhaustion.

### Server Greeting (`buildGreeting`)

`buildGreeting` constructs a valid MySQL Protocol v10 handshake packet that is sent immediately on connect. It must be byte-exact — MySQL clients validate specific offsets and reject malformed greetings. The packet includes:

- Protocol version byte `10`
- Server version string (`5.7.42-0ubuntu0.18.04.1`) null-terminated
- 4-byte connection ID (incremented atomically via `connID atomic.Uint32` to look like a real busy server)
- 8-byte auth salt part 1 (`salt1`) + null byte
- Capability flags (Protocol41, SecureConn, PluginAuth) split across two 2-byte fields with a filler in between
- Charset byte `0x21` (utf8)
- Status flags `0x0002` (autocommit enabled)
- 13-byte auth salt part 2 (`salt2`)
- Plugin name `mysql_native_password` null-terminated

### Authentication (`parseAuthUsername`)

After the greeting, the client sends a handshake response packet. `parseAuthUsername` extracts the username by skipping the first 32 bytes of fixed fields (capability flags, max packet size, charset, reserved) and reading the null-terminated string that follows. The password hash is intentionally ignored — the honeypot always responds with an `okPacket` to let every client in, then publishes `EventLoginSuccess` with the captured username via `publishAuth`.

### Command Loop

After auth, the server enters a read loop dispatching on the first byte of each packet (the command byte):

| Command byte | Constant | Behavior |
|---|---|---|
| `0x01` | `comQuit` | Close connection cleanly |
| `0x02` | `comInitDB` | Publish `USE <db>` command, reply OK |
| `0x03` | `comQuery` | Pattern-match query, return result set or OK |
| `0x0e` | `comPing` | Reply OK (keepalive) |
| anything else | — | Reply with error packet 1047 "Unknown command" |

### Query Handling (`handleQuery`)

`handleQuery` pattern-matches the uppercased query string and returns a `queryResult` struct with column names and row data. Supported queries and their fake responses:

| Query | Response |
|---|---|
| `SELECT @@VERSION...` | `(Ubuntu)` |
| `SELECT DATABASE()` | `mysql` |
| `SELECT USER()` | `root@localhost` |
| `SHOW DATABASES` | `information_schema`, `mysql`, `performance_schema`, `sys` |
| `SHOW TABLES` | 7 system tables (`columns_priv`, `db`, `user`, etc.) |
| `INFORMATION_SCHEMA` queries | Empty result set |
| `SELECT @@DATADIR` | `/var/lib/mysql/` |
| `SELECT @@HOSTNAME` | `ubuntu-server` |
| `SHOW VARIABLES` | version, datadir, hostname, port |

Unrecognized queries return a plain OK packet rather than an error, so automated tools that run arbitrary SQL don't immediately detect the honeypot.

### Result Set Encoding (`writeResultSet`)

`writeResultSet` encodes the `queryResult` using the full MySQL binary result set protocol with correct sequence numbering throughout:

1. Column count packet (length-encoded integer)
2. One `columnDef` packet per column — each uses the `def` catalog and length-encoded strings for all metadata fields
3. EOF packet marking end of column definitions
4. One row packet per result row — each cell is a length-encoded string
5. Final EOF packet

`lenEncInt` and `lenEncString` implement MySQL's variable-length encoding: values under 251 use 1 byte, under 65536 use 3 bytes (`0xFC` prefix), and larger values use 4 bytes (`0xFD` prefix).

### Event Publishing

Four event types are published across the connection lifecycle:

| Event | Topic | Trigger |
|---|---|---|
| `EventConnect` | `TopicConnect` | TCP accept |
| `EventDisconnect` | `TopicDisconnect` | Connection close (deferred) |
| `EventLoginSuccess` | `TopicAuth` | Auth packet received (always accepted) |
| `EventCommand` | `TopicCommand` | `COM_QUERY` and `COM_INIT_DB` |

Only `COM_QUERY` calls `tracker.IncrCommandCount` — ping and init-db are protocol housekeeping and don't count toward the session's command tally shown in the dashboard.

## Building the FTP Honeypot
### Architecture Overview
```
TCP Connection
↓
handleConnection  ← rate limit, session, send banner
↓
readLine          ← parse wire command + argument
↓
dispatch          ← state machine: init → user → auth

↓
publishCommand / publishAuth / publishUpload  ← event bus
```
### State Machine (`handler.go`)

FTP is text-based, which makes it simpler than MySQL but introduces state management. The `ftpConn` struct tracks three states via integer constants:

| State | Value | Transition |
|-------|-------|------------|
| `stateInit` | 0 | Initial — no credentials yet |
| `stateUser` | 1 | `USER` received, username stored |
| `stateAuth` | 2 | `PASS` received, session authenticated |

The `USER` command stores the username and advances to `stateUser`, replying `331 Password required`. The `PASS` command advances to `stateAuth`, always replies `230 logged in`, and returns the password in `cmdResult` so `handleConnection` can call `publishAuth` and `tracker.SetLogin`. Every credential attempt — regardless of what username or password is sent — is accepted and logged.

### Command Dispatch

`dispatch` handles the full FTP command set via a switch statement, returning a `cmdResult` struct that signals special outcomes (quit, password captured, file uploaded) back to the connection loop without coupling the handler to the event bus:

| Command | Behavior |
|---------|----------|
| `USER` / `PASS` | Auth state machine, always accepts |
| `SYST` | Returns `UNIX Type: L8` |
| `FEAT` | Advertises PASV, UTF8, SIZE |
| `PWD` / `XPWD` | Returns current working directory |
| `CWD` / `XCWD` | Path resolution via `resolveFTPPath` |
| `CDUP` | Moves to parent via `parentFTPPath` |
| `TYPE` | Switches ASCII/binary mode |
| `PASV` | Opens ephemeral data listener, returns IP:port |
| `LIST` / `NLST` | Sends fake directory listing over data channel |
| `STOR` | Accepts upload up to 1MB, captures content |
| `RETR` | Returns 550 — no files exist to download |
| `MKD` / `RMD` / `DELE` | Fake success responses |
| `RNFR` / `RNTO` | Fake rename sequence |
| `QUIT` | Sends 221, signals loop to exit |

### PASV Data Channel (`openPASV` / `acceptData`)

PASV mode is the most complex part. `openPASV` opens a new TCP listener on a random ephemeral port (`:0`), then encodes the IP and port into the FTP passive mode format: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`
where `p1 = port/256` and `p2 = port%256`. The client connects to this data channel for directory listings and file uploads. `acceptData` sets a 10-second deadline on the listener before accepting, then closes the listener regardless of outcome to prevent port leaks.

**Known PASV issue in Docker**: `openPASV` derives the advertised IP from `f.ctrl.LocalAddr()`, which returns the Docker bridge IP (e.g. `172.18.0.4`) when running inside a container. FTP clients connecting via `localhost` will see an IP mismatch and refuse the data connection: `227 Entering Passive Mode (172,18,0,4,138,75) Passive mode address mismatch.`

The fix is to read a configured `PassiveIP` from config and use that instead of the local interface address — the standard approach for FTP servers behind NAT or Docker. For local testing, use `ftp -p` (passive with IP override) or connect via the container's bridge IP directly.

### Upload Capture (`recvUpload`)

For `STOR` commands, `recvUpload` accepts data on the data channel via `io.LimitReader` capped at 1MB, then returns the raw bytes to `handleConnection`. The connection loop calls `publishUpload` with filename and content, tagging the event `file-upload` and `mitre:T1105` (Ingress Tool Transfer). This captures malware samples, scripts, and tools that attackers attempt to deploy via FTP after gaining access.

### Fake Directory Listing (`fakeDirListing`)

`fakeDirListing` generates a realistic `ls -la` style output with timestamps derived from `time.Now()` — one month ago for recent entries and six months ago for older ones — so the listing looks like a live system rather than static fixture data. The root `/` listing includes `bin`, `etc`, `home`, `tmp`, `var`, and a `.bashrc` file to mimic a real Ubuntu server.

### Event Publishing

Five event types are published across the connection lifecycle:

| Event | Topic | Trigger | Tags |
|-------|-------|---------|------|
| `EventConnect` | `TopicConnect` | TCP accept | — |
| `EventDisconnect` | `TopicDisconnect` | Connection close (deferred) | — |
| `EventLoginSuccess` | `TopicAuth` | `PASS` command | — |
| `EventCommand` | `TopicCommand` | Every command | — |
| `EventFileUpload` | `TopicFile` | `STOR` with data | `file-upload`, `mitre:T1105` |

Note that every `PASS` is published as `EventLoginSuccess` regardless of the credentials — the honeypot always accepts authentication, so every attempt is by definition a "success" from the attacker's perspective, which is what gets logged for credential intelligence.

## Building the HTTP Honeypot
### Architecture Overview
```
Incoming Request
      ↓
requestLogger middleware  ← captures everything, rate limits, publishes events
      ↓
http.ServeMux router
      ↓
Route handlers (WordPress / phpMyAdmin / sensitive files / default)
```
###  The Core Capture Engine (`middleware.go`)
This is the most important file. Every single request passes through requestLogger before hitting any handler.

What it does per request:

Extracts source IP and port
- Rate limits via `IPLimiter` — returns 429 if the attacker is hitting too fast
- Creates a session in the tracker (start/end lifecycle)
- Reads and buffers the full request body (up to 64KB)
- Spoofs the `Server:` response header to look like a real server
- Captures method, path, query, headers, body, status code, user-agent into a `types.EventRequest` and publishes to the event bus
- Runs scanner detection — if a known tool is identified, publishes a separate `types.EventScan` event tagged with mitre:T1595 (Active Scanning)

###  Scanner Fingerprinting (`scanner.go`)
`DetectScanner(userAgent)` does a case-insensitive substring match against 35+ known tool signatures:

| Category | Tools detected |
|----------|-------------|
| Web scanners | nuclei, nikto, acunetix, openvas, nessus, w3af, arachni |
| Brute forcers | hydra, wfuzz, ffuf, gobuster, dirbuster, feroxbuster |
| Exploit frameworks | metasploit, sqlmap, burpsuite |
| Recon/OSINT | shodan, censys, netcraft, zgrab, masscan |
| Generic clients | curl, wget, python-requests, go-http-client, libwww-perl |
| CMS scanners | wpscan, joomscan |

Returns the tool name (e.g. `"nuclei"`) which gets tagged onto the event as `scanner:nuclei`.

###  Route Setup & Honeypot Persona (`server.go`)
Emulates an Apache/Ubuntu server running WordPress + phpMyAdmin. Routes are designed to match exactly what automated scanners probe first:

WordPress paths:

- `/wp-login.php` — fake login page

- `/wp-admin/` — redirects back to login

- `/xmlrpc.php` — returns XML-RPC fault (looks real)

phpMyAdmin paths:

- `/phpmyadmin/`, `/pma/`, `/phpMyAdmin/` — fake DB login

Sensitive file lures (all return 403 to seem real):

- `/.env`, `/wp-config.php`, `/wp-config.php.bak`, `/config.php`, `/.aws/credentials`, `/server-status`

Git exposure lures (return fake but plausible content):

- `/.git/config` — fake remote origin pointing to a GitHub repo

- `/.git/HEAD` — returns ref: `refs/heads/main`

Other:

- `/robots.txt` — realistic WordPress robots.txt

- `/` — generic "under maintenance" page; anything else returns 404

### WordPress Credential Capture (`wordpress.go`)
- `handleWPLogin` — serves a pixel-perfect WordPress 6.5 login page with `X-Powered-By: PHP/8.1.2`header. POST submissions (credential attempts) get redirected to `/wp-admin/` — the middleware already captured the **username/password** from the body before this runs

- `handleWPAdmin` — redirects back to login (realistic loop)

- `handleXMLRPC` — returns a valid XML-RPC fault response, making it look like a real but locked-down endpoint

### phpMyAdmin Credential Capture (`phpmyadmin.go`)
- Serves a realistic **phpMyAdmin 5.2.1** login page with MySQL 5.7.42 footer

- POST submissions return a 403 with "Cannot log in to the MySQL server" error — again, the middleware already captured `pma_username` and `pma_password` from the body

- Sets `X-Powered-By: PHP/8.1.2` to match the WordPress persona

### Key Design Insight
The handlers themselves **never need to extract credentials** — that's all done transparently in the middleware. The handlers only exist to make the honeypot **look convincing** so attackers keep probing and submitting real credentials/payloads.

## Building the Redis Honeypot
### Architecture Overview
```
TCP Connection
      ↓
handleAccept  ← rate limit, create session, store connState
      ↓
handleCmd     ← dispatch command, publish event, detect exploits
      ↓
handleClose   ← end session, publish disconnect
```
Uses the `redcon` library which speaks the real **RESP protocol** — meaning actual Redis clients connect to it without knowing it's fake.

### Connection Lifecycle (`server.go`)

`handleAccept` — fires when a client connects:

- Rate limits by IP — rejects the connection entirely (returns false) if over limit

- Creates a session in the tracker

- Stores connState (sessionID, srcIP, srcPort, per-connection key store) on the connection object

- Publishes a EventConnect event to the bus

`handleClose` — fires when a client disconnects:

- Ends the session in the tracker

- Publishes a EventDisconnect event

`handleCmd` — fires on every command received:

- Pulls connState from the connection

- Dispatches to handleCommand() to get a response

- Publishes a EventCommand event for every command

- If the command is an exploit command, also publishes a separate EventExploit event

### Command Emulation (`commands.go`)

Implements a believable subset of the Redis protocol with a thread-safe in-memory key store (`safeStore`):

| Command | Behavior |
|---------|----------|
| `PING` | Returns `PONG` or echoes the argument |
| `AUTH` | Returns "no password set" error (looks like unsecured Redis) |
| `INFO` | Returns fake but realistic server info block |
| `SET` / `GET` | Fully functional via `safeStore` |
| `KEYS` | Returns empty array (hides fake data) |
| `DBSIZE` | Returns actual count of stored keys |
| `FLUSHALL` / `FLUSHDB` | Clears the safeStore, returns OK |
| `SELECT` | Returns OK (pretends multi-DB is supported) |
| `SLAVEOF` / `REPLICAOF` | Returns OK (triggers exploit detection) |
| `CONFIG GET` | Returns fake but plausible `dir`, `dbfilename`, `save` values |
| `CONFIG SET` | Returns OK (triggers exploit detection) |
| `EVAL` / `EVALSHA` | Returns NOSCRIPT error |
| `CLUSTER` | Returns "cluster support disabled" |
| `QUIT` | Returns OK and closes connection |

The fake `INFO` response is particularly detailed — it returns a realistic server block with uptime, memory stats, OS info, and process ID to fool automated fingerprinting tools into thinking it's a real Redis instance.

### Exploit Detection (`server.go` + `commands.go`)

Three commands are flagged as exploit attempts via `isExploitCommand()`, each mapped to a MITRE ATT&CK technique:

| Command | Real-world attack | MITRE Tag |
|---------|-------------------|-----------|
| `CONFIG SET` | Change `dir`/`dbfilename` to write crontabs, SSH keys, or deploy cryptominers via RDB dump | `T1059` (Command & Scripting) |
| `SLAVEOF` / `REPLICAOF` | Force the server to replicate from an attacker-controlled Redis master to load malicious modules | `T1021` (Remote Services) |
| `MODULE` | Load a malicious `.so` shared library for RCE | `T1059` |

When triggered, `publishExploit` fires a separate `EventExploit` event to `TopicExploit` with tags like `redis-rce`, `redis-exploit`, `unauthorized-replication` — distinct from the normal `EventCommand` that also fires for the same command. `CONFIG GET` returns `/var/lib/redis` and `dump.rdb` to encourage attackers to proceed with the classic Redis RCE path of changing the dump directory to `/etc/cron.d/` — all of which gets captured as events.

### Key Design Decisions
Per-connection key store (`safeStore`) — each attacker gets their own isolated in-memory Redis that actually responds to `SET`/`GET`. This makes the honeypot convincing for automated tools that probe by setting and reading back keys.

Dual event publishing — exploit commands produce two events: a `TopicCommand` event (always) and a `TopicExploit` event (for exploit commands only). This lets the dashboard count both total commands and specifically dangerous ones without double-counting in the wrong bucket.

`CONFIG GET` returns real-looking paths — responding with `/var/lib/redis` and `dump.rdb` encourages attackers to proceed with the classic Redis RCE technique of changing the dump path to `/etc/cron.d/` — all of which gets captured as events.

## Building the SMB Honeypot

### Architecture Overview
```
TCP Connection (port 445)
↓
handleConnection  ← rate limit, session, 10s read deadline
↓
readNBFrame       ← parse NetBIOS framing
↓
detectVersion     ← SMB1 or SMB2?
↓
extractDialects   ← what versions does the client support?
↓
publishScan       ← emit event with version + dialects
↓
buildNegotiateResponse → writeNBFrame  ← reply and close
```
Deliberately **negotiate-only** — no authentication, no file sharing, no session setup. Just enough to look real to scanners.

### Connection Handling (`server.go`)

`Start` runs a standard TCP listener loop, dispatching each connection to its own goroutine via `go s.handleConnection(conn)`.

`handleConnection` contains the entire per-connection logic:

- Rate limits by IP — silently drops the connection if over limit
- Creates a session and publishes `EventConnect`
- Sets a **10-second read deadline** — prevents slow-loris style hangs where an attacker sends nothing
- Reads one NetBIOS frame, then detects the SMB version — drops the connection silently if it is neither SMB1 nor SMB2, so non-SMB traffic hitting the port is ignored
- Extracts the dialect list from the negotiate request and publishes `EventScan` with version and dialects
- Sends the appropriate negotiate response and closes

There is no `publishDisconnect` — the SMB honeypot does not track disconnects because the connection is always intentionally closed right after the negotiate response.

### NetBIOS Framing (`negotiate.go`)

SMB runs over TCP wrapped in **NetBIOS Session Service** framing — a 4-byte header where bytes 1–3 encode the payload length. `readNBFrame` reads the header, extracts the 3-byte big-endian length, then reads exactly that many bytes, rejecting frames larger than 1MB to prevent memory exhaustion. `writeNBFrame` encodes the response length back into the 4-byte header and writes header and payload in one call.

### Version Detection and Dialect Extraction (`negotiate.go`)

`detectVersion` checks the first 4 bytes of the SMB payload for the magic signature:

| Magic bytes | Version |
|-------------|---------|
| `0xFE 'S' 'M' 'B'` | SMB2 |
| `0xFF 'S' 'M' 'B'` | SMB1 |
| anything else | 0 (unknown, drop) |

`extractDialects` parses the SMB2 negotiate request to extract which dialect versions the client advertises (e.g. `0x0202` = SMB 2.0.2, `0x0210` = SMB 2.1, `0x0300` = SMB 3.0). These are stored as hex strings and included in the scan event — useful for fingerprinting the attacker's OS and tooling since different clients advertise different dialect sets. SMB1 dialect parsing returns nil as it uses a different wire format.

### Negotiate Responses (`negotiate.go`)

`buildSMB2Response` constructs a minimal but valid SMB2 negotiate response (129 bytes: 64-byte header + 65-byte body). It advertises dialect `0x0210` (SMB 2.1), returns a hardcoded server GUID, sets max read/write/transact sizes to 1MB, and sets security mode 7 (signing enabled and required) — making it look like a hardened Windows server.

`buildSMB1Response` constructs a minimal SMB1 negotiate response (69 bytes) with command `0x72` (`SMB_COM_NEGOTIATE`), selecting dialect index 1 with 64KB max buffer sizes.

Both responses are just valid enough for nmap, masscan, and similar tools to fingerprint the service as Windows SMB. Only two event types are published — `EventConnect` on TCP accept and `EventScan` after the negotiate is parsed — both tagged with **MITRE T1595** (Active Scanning), reflecting that SMB port scanning is one of the most common initial reconnaissance techniques.

### Key Design Decision
The deliberate choice to implement **negotiate-only** (no auth, no tree connect, no file I/O) keeps the codebase simple while still capturing 100% of what matters: who is scanning for SMB, what SMB versions they support, and what dialect they advertise — all of which are valuable attacker fingerprints without the 15+ message types a full SMB stack would require.

## MITRE Detection Engine

The detector in `mitre/detector.go` combines two detection strategies.

Single-event rules fire immediately when a matching event arrives. A command event triggers pattern matching against known command categories. The patterns are checked against the uppercased command string, so `wget http://...` matches the "WGET " pattern in `isToolTransfer()`, mapping to T1105.

Multi-event rules maintain per-IP state. The `ipState` struct has two fields: `authHits` (a slice of timestamps) and `services` (a map of service types to their last-seen time). On each authentication event, the timestamp is appended to `authHits`, old entries outside the 5-minute window are pruned, and if 5 or more remain, T1110 (Brute Force) is detected. On each connection event, the service type is recorded, and if 3 or more distinct services have been contacted within 60 seconds, T1046 (Network Service Discovery) is detected.

The detector uses a mutex to protect the per-IP state map, since events from different services arrive on different goroutines.

`Detect` returns `[]*types.MITREDetection` rather than plain technique ID strings. Each object is fully populated: session ID, technique ID, tactic resolved from the embedded index (`reconnaissance`, `credential-access`, `execution`, etc.), confidence (100 for all rule matches), source IP, service type, the triggering event type as evidence, and detection timestamp. The processor uses these objects two ways: technique IDs are appended to the event's `Tags` slice so they survive in the event record for filtering, and each detection is persisted to the `mitre_detections` table via `InsertDetection` so the MITRE heatmap has real data to render.

## STIX Export

The `intel/stix.go` file generates STIX 2.1 bundles as JSON. A bundle contains an Identity SDO (representing the honeypot system) and one Indicator SDO per IOC.

Each indicator includes a STIX pattern expression. For IPv4 addresses, the pattern is `[ipv4-addr:value = '1.2.3.4']`. For file hashes, it is `[file:hashes.'SHA-256' = 'abc...']`. For user-agents, the pattern navigates to `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '...']`.

UUIDs are generated using UUID v4 via `uuid.New()` from the google/uuid library. Each object gets a type prefix: `identity--uuid`, `indicator--uuid`, `bundle--uuid`. UUID v4 is the correct choice here: STIX 2.1 (Section 2.9) specifies that random identifiers must use UUIDv4 and deterministic identifiers must use UUIDv5. UUID v7 (time-ordered) is not a permitted STIX identifier format and would cause ingestion failures in strict platforms like OpenCTI.

## Event Bus Internals

The bus uses Go's `sync.RWMutex` for subscriber management. Publishing takes a read lock (allowing concurrent publishes), while subscribing takes a write lock. The publish path iterates over all subscribers, checks if the subscriber's topic set includes the event's topic or the wildcard "all" topic, and sends to the channel with a non-blocking select.

```go
select {
case sub.ch <- ev:
default:
}
```

The `default` case means if the channel is full, the event is silently dropped for that subscriber. This is the key design decision: producers are never blocked by slow consumers.

## Session Tracking

The `session.Tracker` is a thread-safe in-memory map from session ID to `types.Session`. It uses an `RWMutex` with read locks for lookups and write locks for mutations.

Persistence is wired through two callbacks registered at startup in `serve.go`. `SetOnStart` fires when `Start()` creates a new session — the serve command wires this to `pgStore.InsertSession`, writing the initial record (IP, port, service type, start time) to PostgreSQL before the attacker has even authenticated. `SetOnEnd` fires when `End()` removes the session — wired to `pgStore.UpdateSession`, which flushes the final state: command count, MITRE techniques, threat score, username, and end timestamp.

During a session, services call `IncrCommandCount()`, `SetLogin()`, and `AddTechnique()` to accumulate state in the in-memory struct. When the connection closes, `End()` removes it from the map and fires `onEnd` with the mutex already released, so the database write never blocks other sessions from starting or ending concurrently.

The tracker's `Active()` method returns a snapshot of all in-progress sessions, used by the dashboard's "active sessions" counter.

## Rate Limiting

The per-IP rate limiter uses `golang.org/x/time/rate.Limiter` (token bucket algorithm). Each IP gets its own limiter, created on first connection. A background goroutine runs every 10 minutes and removes limiters for IPs that have not been seen recently, preventing memory growth.

The rate limiter protects the honeypot from resource exhaustion. An attacker sending 10,000 connections per second would generate 10,000 events, each requiring GeoIP lookup, MITRE detection, and database insert. The limiter caps this at 10 events per second per IP.

## Frontend Architecture

The React frontend uses a layered architecture:

**Core layer**: Axios HTTP client with a response interceptor that normalizes errors into typed `ApiError` objects. React Router v7 browser router. A Zustand WebSocket store that maintains a buffer of the 200 most recent live events and a running total event counter. The WebSocket store implements exponential backoff reconnection starting at 1 second and capping at 30 seconds, so the dashboard recovers automatically from backend restarts without a page refresh.

**API layer**: TypeScript type definitions mirroring Go types, and TanStack Query v5 hooks for each endpoint. Hooks use named query strategies defined in `config.ts`: `live` (10s stale, 10s refetch) for the event feed, `dashboard` (15s) for overview stats, `slow` (60s) for country and credential aggregates, and `static` (infinite stale, no refetch) for the MITRE technique catalog. Query and mutation errors are surfaced automatically through Sonner toast notifications wired into the TanStack Query cache error handlers, so API failures always reach the user without per-hook error handling.

**Component layer**: Reusable UI components (StatCard, ServiceBadge, EventFeed, AttackMap, SessionPlayer) that compose into pages. The AttackMap uses react-leaflet. The SessionPlayer uses xterm.js to replay asciicast v2 recordings with play/pause/speed controls.

**Page layer**: Six pages (Dashboard, Events, Sessions, Attackers, MITRE, Intel) that combine components with data from hooks.

**Tooling**: Biome handles both linting and formatting (replacing ESLint + Prettier with a single config). Zod v4 validates API response shapes at the boundary. SCSS modules with OKLCH color tokens (`_tokens.scss`) provide the design system — OKLCH gives perceptually uniform color manipulation for the threat severity palette.

## Build and Deploy

Development:
```bash
just dev-up          # This spins up the full stack using dev.compose.yml — PostgreSQL, Redis, the Go backend (with Air hot-reload), and the Vite frontend dev server all in containers. 
just dev-serve       # Run backend locally (needs Postgres + Redis). This runs the Go backend directly on your machine, but requires PostgreSQL and Redis to already be running somewhere (either locally or via just dev-up for just the infrastructure containers).
cd frontend && pnpm dev  # Starts Vite's dev server with a proxy configured in vite.config.ts that forwards /api/* and /ws/* to the backend on port 8000. This means you can hit localhost:5173 and the browser doesn't deal with CORS — the Vite dev server acts as a reverse proxy. 
```

Production:
```bash
just up -d           # Multi-stage Docker build + nginx reverse proxy
```

The production build compiles the Go binary with `CGO_ENABLED=0` into a `scratch` container (no OS, just the binary), and builds the React app into static files served by nginx. The nginx config proxies `/api/*` to the backend and `/ws/*` with WebSocket upgrade headers.
