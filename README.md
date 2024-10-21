## SecureDrop Protocol in Rust

This is a very, very, work in progress port of the [SecureDrop Protocol](https://github.com/freedomofpress/securedrop-protocol) demo code to Rust.

Don't use it for anything.

## Getting started

Once you have Rust installed, you can generate the initial key heirarchy with:

```
cargo run --bin initialize_keys
```

This will create a `root` key pair, an `intermediate` key pair (signed by `root`), and individual journalist key pairs (signed by `intermediate`).

## License
Available under the AGPL, v3 or (at your option) any later version. See COPYING for more details.

(C) 2024 Freedom of the Press Foundation & Kunal Mehta
