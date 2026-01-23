## 0.0.1

* Online!

## 1.0.0

* The entire structure was redesigned from scratch.

## 1.0.1

* Err fix

## 1.0.2

* Err fix

## 1.2.0

> **Minor Update:** Revani Client has evolved into a full BaaS (Backend-as-a-Service) SDK.

- **Identity Management (`client.user`)**: Added support for end-user registration, login, secure profile management, and password changes.
- **Social Graph Features (`client.social`)**: Introduced methods for creating posts, commenting, liking (toggle logic), and view counting.
- **Messaging System (`client.chat`)**: Added full support for chat room creation, message sending/editing/deleting, emoji reactions, and message pinning.
- **Bulk Data Operations**: Added `addAll`, `getAll`, and `deleteAll` methods to `RevaniData` for high-performance batch processing.
- **Architecture**: Organized client structure into dedicated modules (`.user`, `.social`, `.chat`, `.data`, `.storage`, `.livekit`, `.pubsub`).


## 2.0.0

> **Major Update:** Hybrid Infrastructure, Token-based Security, and SDK Modernization.

### 🏗️ Hybrid Infrastructure & Architectural Changes
- **Storage Decoupling**: Migrated file operations (Upload/Download) from raw TCP sockets to a dedicated **HTTP REST API** layer. This eliminates "Head-of-line blocking" during large binary transfers.
- **Side-Kitchen HTTP Server**: Integrated a high-performance HTTP service within the server core to handle stateless requests and media streaming.

### 🔐 Security & Identity Management
- **Token-Based Authentication**: Transitioned from static session keys to a dynamic **Token** system for all administrative and user logins.
- **Session Heating (Hot TTL)**: Implemented active session management where tokens in `sys_sessions` automatically renew their expiration upon verification.
- **Identity Mismatch Detection**: Added strict cross-verification between encrypted packet `accountID` and active session ownership to prevent impersonation.

### 📦 Dart SDK / Client Refactoring
- **RevaniResponse Modernization**: The SDK now returns type-safe `RevaniResponse` objects instead of raw `Map` data, standardizing status codes and error messaging.
- **Robust Callbacks**: Introduced `SuccessCallback` and `ErrorCallback` types for declarative asynchronous flow management.
- **Auto-Reconnect**: Added intelligent reconnection logic featuring an **Exponential Backoff** algorithm for stable socket persistence.
- **Time Synchronization**: Implemented `_serverTimeOffset` to calculate clock drift, enabling millisecond-precision protection against Replay Attacks.

### ⚡ Performance & Optimization
- **Standardized Status Codes**: Responses now utilize HTTP-compliant codes (e.g., 200, 401, 403) for consistent debugging.
- **Payload Processing**: Refactored `_onData` buffer logic to reliably handle interleaved encrypted and plain-text packets.

### ⚠️ Breaking Changes
- `execute` method now returns a `RevaniResponse` object.
- `login` function now returns a `RevaniResponse` (was `bool`), providing detailed failure reasons.
- Storage-related commands are now handled via **HTTP endpoints** instead of the TCP `execute` command.

## 2.0.1

> Err fix

## 2.1.0

> Security and improvements.


## 2.1.1

> Revani client dart updated

## 2.1.2

> Fix 2026-01-23

## 2.1.3

> Fix 2026-01-23

## 3.0.0

> **Major Update:** AOT Compilation, Turbocharged Authentication, and Identity Shielding.

### 🏗️ AOT Compilation & Binary Packaging
- **Native Binary Execution**: The `server/run.dart` management suite now compiles the entire project into a native executable (`server.exe`). This eliminates Dart VM warm-up times and allows the engine to run directly on hardware.
- **Turbocharged Performance**: By switching from JIT to **Ahead-Of-Time (AOT)** compilation, the database engine and security pipelines now operate at peak CPU frequency with zero interpreter overhead.

### 🔐 Advanced Identity Protection
- **Identity Theft Prevention**: Implemented a strict "Lock & Key" mechanism that cross-verifies the `accountID` inside encrypted packets against the authorized `sessionOwnerID`.
- **Impersonation Block**: The server now automatically detects and rejects any attempts to manipulate data using a session that does not match the provided Account identity.

### ⚡ Turbocharged Login & Security
- **High-Speed Authentication**: Re-engineered the Argon2id hashing parameters and worker isolate communication, reducing login latency from several seconds to a few hundred milliseconds.
- **Efficient Security Pipelines**: Optimized the AES-GCM 256-bit encryption/decryption flow for the AOT environment, ensuring near-instant response times for stateful commands.

### 📦 Hardened Storage Operations
- **Guaranteed Delivery**: Storage operations are now more robust with enhanced asynchronous file-locking and integrity checks, ensuring 100% reliability during file transfers.
- **Side-Kitchen Resilience**: Hardened the HTTP REST layer to prevent throughput bottlenecks during massive concurrent binary uploads.

### 🛠️ Client & SDK Synchronization
- **Protocol Alignment**: Updated the Revani Dart SDK to perfectly synchronize with the new AOT-packaged server structures and refined status code logic.
- **Enhanced Debugging**: Improved error propagation within the client, providing more granular insights into server-side kitchen accidents.

### ⚠️ Breaking Changes
- **Execution Path**: For production environments, the server must now be started via the **AOT (Option 2)** in `run.dart` for intended performance levels.
- **Binary Dependency**: The system now generates a `bin/server.exe` which is required for high-speed "Live Mode" execution.