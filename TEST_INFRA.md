# TEST_INFRA — E2E Testing Framework & Specification

## 1. Testing Philosophy & Strategy

This test suite implements a strictly **opaque-box, requirement-driven** verification methodology for the Web-based NVR/VMS application. Tests are derived directly from `ORIGINAL_REQUEST.md` and `PROJECT.md`, verifying observable system behavior, REST/WebSocket API contracts, security invariants, streaming continuity, and file storage integrity without binding to internal implementation details.

### Test Methodologies Applied
- **Category-Partitioning**: Input domain decomposition into valid classes, equivalence partitions, and boundary subsets for credentials, protocol schemas, media formats, and stream states.
- **Boundary Value Analysis (BVA)**: Probing extrema including 0-byte video buffers, 1-byte headers, 600,000 PBKDF2 iterations, disk quota exhaustion (99.9% full), lease expiration windows ($T-30s$, $T=0$, $T+10s$), 8-direction PTZ angles, and pagination edge cases.
- **Pairwise Combinatorial Testing**: Verification of multi-variable interactions across vendor clouds (EZVIZ, Xiaomi CN, Xiaomi Global, Generic RTSP, ONVIF), streaming transports (WebRTC, MSE, HLS), and NVR recording modes (Manual, Scheduled, AI-Triggered).
- **Adversarial & Fault Injection**: Simulating upstream socket resets, corrupted encryption tags, expired JWT/session tokens, non-responsive ONVIF endpoints, malformed SDP negotiations, and storage permission faults.
- **Real-World Workloads (Tier 4)**: 24/7 continuous surveillance simulation, rapid multi-cam layout thrashing, storage FIFO quota purging under disk pressure, and high-frequency AI alert storms.

---

## 2. Test Architecture & Directory Layout

```
g:\NAS_APP\Live_Camera_Viewing_Recording\
├── TEST_INFRA.md                   # This framework specification
├── TEST_READY.md                   # Formal test suite completion declaration
└── tests_e2e/
    ├── __init__.py
    ├── conftest.py                 # Pytest fixtures, test client, lifecycle, temporary storage
    ├── mocks/
    │   ├── __init__.py
    │   └── mock_camera_server.py   # Deterministic mock servers (EZVIZ, Xiaomi, ONVIF, go2rtc, RTSP)
    ├── test_tier1_features.py      # Tier 1: Happy-path feature coverage (>=5 tests per feature, 165+ tests)
    ├── test_tier2_boundaries.py    # Tier 2: Boundary, timeout, corruption & error cases (165+ tests)
    ├── test_tier3_combinations.py  # Tier 3: Cross-feature interaction tests (20+ tests)
    └── test_tier4_scenarios.py     # Tier 4: Realistic surveillance operational scenarios (10+ tests)
```

### Deterministic Test Doubles & Mocks
To guarantee 100% test reproducibility with zero external hardware or network dependencies:
1. **MockEZVIZServer**: Emulates EZVIZ Open Platform endpoints (`/api/lapp/token/get`, `/api/lapp/camera/list`, `/api/lapp/live/address/get`, `/api/lapp/device/encrypt/off`, `/api/lapp/device/ptz/*`).
2. **MockXiaomiServer**: Emulates Xiaomi Passport authentication (`serviceLogin`, `serviceLoginAuth2`), regional cloud gateways (`cn`, `de`, `i2`, `ru`, `sg`, `us`), signed MIoT device listings, and MIoT-Spec action RPCs.
3. **MockONVIFServer**: Emulates WS-Discovery multicast probes on UDP 3702 and SOAP Media/PTZ service endpoints (`GetProfiles`, `GetStreamUri`, `ContinuousMove`, `Stop`).
4. **MockGo2rtcServer**: Emulates go2rtc Media Gateway REST API (`/api/streams` PUT/PATCH/DELETE, `/api/frame.jpeg`, `/api/webrtc`).
5. **MockRTSPServer**: Emulates RTSP streaming server handshakes and synthetic video stream pipelines.

---

## 3. Feature Inventory & Test Mapping (Features 1–33)

| # | Feature Name | Tier 1 (Feature Coverage >=5) | Tier 2 (Boundaries & Corners >=5) | Tier 3 (Cross-Feature Pairwise) | Tier 4 (Real-World Workload) |
|---|--------------|-------------------------------|-----------------------------------|---------------------------------|------------------------------|
| 1 | DB Schema & Initialization | SQLite WAL mode, tables creation, constraints, foreign keys, schema migrations | Disk full on init, corrupted DB header, read-only DB file, concurrent writers, invalid SQL table injection | Account + Camera DB cascade | DB recovery on abrupt reboot |
| 2 | Credential Vault & Encryption | AES-256-GCM encryption, decryption round-trip, random nonce, PBKDF2 derivation, salt uniqueness | Tampered ciphertext, bad auth tag, empty secret, 10MB secret, wrong master password | Vault secret stored in DB & used for Cloud Auth | Vault secret rotation under active streaming |
| 3 | go2rtc Process & Lifecycle Manager | Executable path resolution, process startup, port 1984 health check, graceful SIGTERM, restart on crash | Port 1984 conflict, missing binary, zero-byte binary, kill -9 unexpected termination, slow startup timeout | go2rtc lifecycle + StreamKeeper monitoring | 24-hour crash-restart simulation |
| 4 | go2rtc REST API Client | Add stream (PUT), update stream (PATCH), delete stream (DELETE), query stream list, get frame JPEG | Special character stream names, 404 stream not found, malformed upstream URL, timeout on go2rtc REST, duplicate stream add | Cloud token renewal + PATCH hot-swap | 64-channel simultaneous stream management |
| 5 | FFmpeg 7.1 Resolution & Tools | Bundled executable detection, version string parsing (7.1+), codec check (h264, aac), sub-process runner, output validation | Missing ffmpeg binary, execution permission denied, non-zero exit code, corrupted stream input, SIGKILL on freeze | FFmpeg recording + NVR storage quota | Continuous 4K fMP4 chunking |
| 6 | Backend App Skeleton & Security | FastAPI startup/lifespan, CORS headers, CSP headers, SlowAPI rate limiting, standard error envelope | Extreme rate limit flood, malformed JSON body, oversized HTTP headers, SQL injection payloads, XSS probe in query | Auth session + rate limiter + camera API | Multi-tenant concurrent dashboard access |
| 7 | EZVIZ Cloud OpenAPI Integration | AppKey/Secret auth, token refresh, camera listing, online status detection, live stream URL extraction | Invalid AppKey, expired token, network timeout, rate-limited cloud API (429), empty camera list | EZVIZ Auth + go2rtc stream registration | Cloud gateway token renegotiation during live view |
| 8 | EZVIZ Device Control & Encryption | Decryption code validation, encryption toggle off (`encrypt/off`), PTZ start/stop, PTZ speed parameter, channel routing | Invalid verification code, device offline during PTZ, command timeout, unauthorized device ID, conflicting PTZ commands | EZVIZ encryption off + go2rtc H.264 stream | Operator PTZ pan-tilt track & zoom |
| 9 | Xiaomi Passport Authentication | 2-step login, MD5 hash calculation, serviceToken extraction, ssecurity derivation, session cookie preservation | Invalid username/password, Captcha challenge trigger, 2FA prompt handling, network timeout on passport, account locked | Xiaomi Auth + Regional sync + Stream mapping | Recurring re-auth token cycle |
| 10 | Xiaomi Mi Home Device Sync | Multi-region support (`cn`, `de`, `i2`, `ru`, `sg`, `us`), HMAC-SHA256 request signing, device filtering, DID mapping, online state | Non-existent region, signature mismatch, partial region outage, malformed JSON response, 500+ device pagination | Xiaomi Device Sync + go2rtc stream generation | Cross-region multi-camera home sync |
| 11 | Xiaomi Stream & PTZ Integration | `xiaomi://` protocol mapping, MIoT-Spec action RPC, pan/tilt movement, speed setting, preset navigation | MIoT RPC timeout, unsupported PTZ action ID, device busy error, invalid siid/aiid parameters, connection dropped | Xiaomi PTZ + Live player HUD | Real-time pan-and-tilt tracking |
| 12 | Generic RTSP Stream Support | RTSP URL parsing, embedded auth credentials, port handling, go2rtc stream registration, stream validation | Malformed RTSP URL, unreachable host, invalid username/password, RTSP port 554 blocked, unsupported codec | RTSP camera add + go2rtc player WebRTC | Flaky RTSP link automatic reconnect |
| 13 | ONVIF WS-Discovery Probe | UDP 3702 multicast probe, XML ProbeMatches parsing, XAddrs extraction, device deduplication, async timeout | Zero devices discovered, broadcast storm filter, malformed XML SOAP response, UDP packet truncation, unreachable IP | ONVIF Discovery -> Auto-add camera | Network interface scan & subnet rediscovery |
| 14 | ONVIF Media & PTZ Services | SOAP GetProfiles, GetStreamUri, ContinuousMove, Stop commands, PTZ space configuration | SOAP Fault 500, unsupported ContinuousMove, profile token not found, auth digest failure, network lag during PTZ | ONVIF profile -> RTSP URI -> go2rtc player | Interactive joystick PTZ navigation |
| 15 | 24/7 StreamKeeper Daemon | Proactive renewal at T-30s, lease tracking, PATCH /api/streams hot-swap, zero client disruption, multi-stream daemon loop | Upstream renewal failure, abrupt stream disconnect, negative lease duration, lease clock skew, backoff retry | StreamKeeper renewal + active WebRTC player | 15-minute continuous bypass endurance test |
| 16 | Zero-Timeout LAN RTSP Routing | LAN RTSP priority detection, fallback to cloud on LAN failure, local IP discovery, latency optimization, credential extraction | LAN RTSP offline fallback, IP collision, wrong local RTSP port, credentials mismatch on LAN, firewall block | LAN RTSP + StreamKeeper bypass | Automatic LAN/Cloud failover and fallback |
| 17 | Crash-Resilient MP4 Recording | Manual start/stop recording, fragmented MP4 (`fMP4`) container flags, faststart MOOV atom relocation, audio/video sync, playable MP4 | Abrupt process termination (SIGKILL), 0-byte video stream, corrupt audio track, disk full during write, invalid file path | Live stream -> fMP4 recording -> playback verify | 24-hour segment rotation without frame loss |
| 18 | Scheduled & Event-Based Recording | Schedule rule evaluation, AI event trigger recording, pre/post buffer duration, stop on schedule expiry, overlap handling | Past schedule date, conflicting schedule rules, rapid event burst triggers, zero-duration recording, timezone changes | AI Human event -> Automatic 30s MP4 record | Multi-camera scheduled night recording shift |
| 19 | High-Resolution Snapshot Engine | Instant frame capture via `/api/frame.jpeg`, Pillow 320x180 thumbnail generation, timestamp watermark, metadata tagging, JPEG validity | Corrupted JPEG frame from gateway, 0-byte frame, unreadable stream name, snapshot directory unwritable, high concurrency | AI Event trigger -> Instant snapshot -> Log | Burst snapshot during high-speed movement |
| 20 | Storage Hierarchy & FIFO Retention | Local storage path, NAS UNC path (`\\nas\share`), quota calculation, FIFO deletion of oldest clips, protected clips flag | Storage completely full (0 bytes free), NAS network disconnect mid-write, read-only permissions, locked file deletion, invalid UNC path | NVR Recording + Storage Quota FIFO purge | Long-term circular buffer retention on NAS |
| 21 | Canonical AI Event Normalization | Vendor code normalization into `Human`, `Movement`, `Abnormal Sound`, metadata extraction, confidence scoring | Unknown vendor event code, empty event payload, conflicting alert types, timestamp in future/past, duplicate alerts | Cloud alert -> Canonical event -> DB log | High-density multi-vendor event normalization |
| 22 | AI Event Logging & SQLite Storage | Event log table insert, camera relationship, indexed timestamp query, snapshot/clip URL association, batch logging | SQL injection in event description, missing foreign key camera, huge metadata blob, concurrent SQLite inserts, corrupt log | AI Event -> SQLite insert -> Event search | Million-row event storage & query performance |
| 23 | Universal Event Search & Filter | Multi-column text search, date-time range filter, camera ID filter, event type filter, pagination (`page`, `page_size`) | Inverted date range (start > end), negative page number, huge page size (10,000), special regex characters in query, empty result | Event Logging + Search API + Filter | Rapid interactive surveillance log investigation |
| 24 | 3-Mode Event Export | Mode 1 (Template only), Mode 2 (Filtered view), Mode 3 (All records), CSV and XLSX format verification, column ordering | Export 0 records, export 100,000 records, special characters in CSV, formulas injection (`=CMD`), invalid mode parameter | Filtered Search -> 3-Mode Export | Audit trail compliance export |
| 25 | Real-time Alert Broadcast | WebSocket connect & broadcast, SSE fallback stream, toast payload structure, audio alert flag, badge counter update | Client disconnect mid-stream, slow WebSocket client buffer, 100 simultaneous connected clients, malformed payload, auth failure | AI Event occurrence -> Real-time WS toast | Security Operations Center multi-client broadcast |
| 26 | Modern Surveillance UI Console | Dark Theme styling verification (`#07090e`, `#0f131c`), glassmorphic CSS rules, HUD OSD telemetry layout, responsive CSS classes, DOM accessibility | Mobile viewport resize, tablet landscape/portrait, high-DPI zoom (200%), missing stylesheet fallback, CSS injection attempt | UI Console + Multi-cam grid + Player component | Operator continuous monitoring layout |
| 27 | Multi-Camera Grid View | 1x1, 2x2, 3x3, 4x4 layout modes, fullscreen toggle, single-cam focus expand, layout state persistence, video container aspect ratio | Grid with 0 cameras, grid with 64 cameras, rapid layout toggle stress, invalid grid size, viewport zero width | Camera listing + Grid layout + Stream player | 16-channel video wall operations |
| 28 | Interactive PTZ Control Deck | 8 directional buttons (N, NE, E, SE, S, SW, W, NW), zoom in/out, speed slider [1..10], deadman safety release, disabled for fixed cams | Simultaneous opposing directions, speed out of bounds (-1, 100), mouse release outside button (deadman), network drop during move, fixed camera click | PTZ UI click -> ONVIF/Cloud PTZ API call | Precision PTZ tracking and patrol |
| 29 | Video Player HUD & OSD Telemetry | WebRTC `<video-rtc>` tag, MSE fallback, OSD overlay (FPS, Bitrate, Latency, Connection Status), play/pause controls, snapshot button | WebRTC negotiation failure -> MSE fallback, audio codec unsupported, zero bitrate detection, video freeze recovery, player unmount cleanup | go2rtc WebRTC stream -> Video Player HUD | Low-latency live viewing with real-time HUD |
| 30 | Camera & Account Management UI | Add camera modal, Edit camera settings, Delete camera, Cloud account login dialog (EZVIZ, Xiaomi region selector), ONVIF discovery list | Empty mandatory fields, invalid IP address, duplicate camera name, delete camera while recording, special chars in name | Account login -> Device sync -> Auto-add camera | Full camera fleet onboarding and configuration |
| 31 | Native Packaging & Runner Scripts | Windows launcher (`run_app.bat`), PowerShell launcher (`run_app.ps1`), port 8000 binding, environment validation, graceful stop | Missing python environment, port 8000 already bound, missing bin/ directory, execution policy restricted, Ctrl+C trap | Native launcher -> FastAPI start -> go2rtc init | Clean bootstrap and shutdown verification |
| 32 | Containerized Docker Deployment | Multi-stage Dockerfile syntax, docker-compose.yml service definitions, volume mount bindings (`recordings`, `data`, `snapshots`), port mappings (8000, 1984, 8554) | Missing environment variables, read-only volume mounts, non-root user permissions, container restart policy, network isolation | Docker compose environment -> App startup | Cloud/Edge containerized NVR deployment |
| 33 | User Global Rules Compliance | `changelog.md` format, `rules.md` specs, `DATA_MAPPING.md` 4-tier mappings, version bump (`v0.xxx`), direct port 8000 binding check | Missing changelog header, unversioned static assets, unmapped database column, background zombie process on 8000, missing requirements.txt | Full app lifecycle + User Rules compliance | Production release readiness audit |

---

## 4. Test Execution & Invocation

### Command-line Runner Invocation
```bash
# Execute entire E2E test suite with verbose output
pytest tests_e2e/ -v

# Run individual tiers
pytest tests_e2e/test_tier1_features.py -v
pytest tests_e2e/test_tier2_boundaries.py -v
pytest tests_e2e/test_tier3_combinations.py -v
pytest tests_e2e/test_tier4_scenarios.py -v

# Run with test report generation
pytest tests_e2e/ -v --durations=10
```

### Pass/Fail Acceptance Criteria
- **100% Pass Rate**: All test cases must pass with zero errors and zero unhandled exceptions.
- **Zero Flakiness**: All tests must use deterministic mocks, predictable timestamps, and clean temporary fixture isolation.
- **Execution Speed**: Full suite execution must complete within reasonable time limits (<60 seconds total) through asynchronous I/O and efficient in-memory fixtures.

---

## 5. Real-World Application Scenarios (Tier 4)

| Scenario ID | Scenario Name | Description & Operational Flow | Expected System Behavior |
|-------------|---------------|--------------------------------|--------------------------|
| `SCEN-01` | 24/7 Security Shift Live Monitoring | Operator monitors 4 cameras simultaneously across EZVIZ, Xiaomi, and ONVIF sources for 15+ simulated minutes with periodic cloud lease refreshes. | All 4 streams maintain active state; StreamKeeper hot-swaps upstream URLs without video drop; WebRTC latency stays <500ms. |
| `SCEN-02` | Intrusion Event Detection & Automated Response | AI camera detects "Human" movement. Gateway triggers instant snapshot, creates canonical event log, sends WebSocket toast alert, and starts 30s MP4 recording. | Event log created with snapshot URL; WebSocket push received with correct badge; playable fMP4 recording saved in `recordings/`. |
| `SCEN-03` | Network Flap & Cloud Auto-Recovery | Upstream cloud disconnects momentarily during live view. StreamKeeper detects drop, applies exponential backoff, re-authenticates, and restores stream. | Player receives reconnected stream; system logs reconnection event; zero backend memory leaks or zombie processes. |
| `SCEN-04` | High-Density Multi-Camera Grid Thrashing | Operator rapidly switches grid layouts (1x1 -> 4x4 -> 2x2 -> Fullscreen) while adjusting PTZ controls on active camera. | Zero WebRTC connection leaks; DOM elements mount/unmount cleanly; PTZ deadman stop halts camera movement on switch. |
| `SCEN-05` | Long-Term Storage Quota & FIFO Pruning | Continuous recording reaches 95% of allocated storage quota (Local/NAS). System activates FIFO purge engine. | Oldest non-protected recordings deleted first; free space restored to safe margin; active recording writes without corruption. |
| `SCEN-06` | Multi-Vendor Fleet Discovery & Provisioning | Administrator discovers ONVIF cameras via UDP multicast, logs into EZVIZ and Xiaomi cloud accounts, and syncs 12 cameras in single session. | All cameras classified and stored in DB; encrypted credentials stored in vault; streams registered into go2rtc media gateway. |
| `SCEN-07` | Comprehensive Security Audit & Event Export | Security manager filters events by date range, camera, and type "Human", reviews snapshots, and exports 3-mode CSV and Excel XLSX reports. | Exported CSV and XLSX contain verified headers, matching row counts, sanitized formulas (`=CMD` injection neutral), and valid timestamps. |
| `SCEN-08` | Disaster Recovery & Database Resiliency | Application experiences sudden simulated power outage (SIGKILL) during active recording and database write operations. | SQLite WAL journal recovers without corruption; fMP4 video chunk remains playable via faststart MOOV atom; vault keys intact. |

---

## 6. Coverage Thresholds

| Metric | Target Requirement | Verification Mechanism |
|--------|--------------------|------------------------|
| **Feature Coverage (Tier 1)** | $\ge 5$ tests per feature (33 features = 165+ tests) | Automated pytest count in `test_tier1_features.py` |
| **Boundary & Corner Cases (Tier 2)** | $\ge 5$ tests per feature (33 features = 165+ tests) | Automated pytest count in `test_tier2_boundaries.py` |
| **Cross-Feature Combinations (Tier 3)** | $\ge 20$ multi-system interaction tests | Automated pytest count in `test_tier3_combinations.py` |
| **Real-World Scenarios (Tier 4)** | $\ge 8$ end-to-end operational scenarios | Automated pytest count in `test_tier4_scenarios.py` |
| **Total Test Suite Volume** | $\ge 350$ comprehensive test cases | Overall pytest execution summary |
| **Flakiness Rate** | 0% (Deterministic mocks and isolated temp dirs) | Multi-run stability validation |
