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