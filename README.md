# sunder

A high-assurance messaging protocol combining **End-to-End Encryption** with **Server-Side Moderation**.

Built on [MLS](https://www.rfc-editor.org/rfc/rfc9420.pdf) and [QUIC](https://www.rfc-editor.org/rfc/rfc9000.pdf) which allows servers to cryptographically enforce bans, ordering, and group membership without accessing message content.

Prioritizes correctness through **Deterministic Simulation Testing** and a **Sans-IO** architecture.

## Architecture

- **Hub-Centric:** Servers enforce total ordering and moderation via MLS External Commits.
- **Sans-IO:** Protocol logic (`sunder-core`) is pure, synchronous, and decoupled from network/time.
- **Zero-Copy:** Wire format (`sunder-proto`) designed for O(1) routing.

## Workspace Structure

- `crates/sunder-core`: Pure protocol state machines (Connection, MLS).
- `crates/sunder-proto`: Wire format definitions and serialization.
- `crates/sunder-harness`: Deterministic simulation runner (using `turmoil`).
- `crates/sunder-server`: Production server runtime (using `quinn` + `tokio`).

### Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Protocol Specification](docs/PROTOCOL.md)
- [Implementation Roadmap](IMPLEMENTATION_PLAN.md)

## License

[Apache 2.0](LICENSE)
