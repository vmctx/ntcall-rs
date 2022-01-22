# ntcall-rs

Easily call NT System Calls from rust.

[![Crates.io][crates-badge]][crates-url]

[crates-badge]: https://img.shields.io/crates/v/ntcall
[crates-url]: https://crates.io/crates/ntcall

All System Call ID’s are dumped at compile-time. To get started just import the function you would like to use and call it just like with winapi/ntapi.

## Usage
To use `ntcall-rs`, first add this to your `Cargo.toml`:

```toml
[dependencies]
ntcall = "0.1"
```
## Example
Shutting down your PC with a System Call.
```rust
use ntcall::NtShutdownSystem;

const ShutdownPowerOff: u32 = 2;

unsafe { NtShutdownSystem(ShutdownPowerOff); }
```
## License

This project is licensed under the [MIT license](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `ntcall-rs` by you, shall be licensed as MIT, without any additional
terms or conditions.
