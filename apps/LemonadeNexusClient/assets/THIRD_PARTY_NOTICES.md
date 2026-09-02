# Third-Party Notices

Lemonade-Nexus is licensed under the Lemonade-Nexus Source-Available License
(see `LICENSE`). It incorporates the third-party components listed below, which
are licensed under their own terms. Those terms are reproduced at the end of
this file. This file must be distributed with every binary release of the
server, sidecar, client SDK, and client application.

Nothing in the Lemonade-Nexus license restricts any right that a third-party
component's own license grants you with respect to that component.

Generated from `cmake/libraries/*.cmake`, `crates/*/Cargo.lock`, and
`apps/LemonadeNexusClient/pubspec.lock`. Regenerate after changing any
dependency.

## 1. Native libraries

Linked into the server (`lemonade-nexus`), the sidecar, and the client SDK
library that the desktop client embeds.

| Component | Version | License | Copyright |
|---|---|---|---|
| [OpenSSL](https://www.openssl.org/) | 3.3.2 | Apache-2.0 | Copyright (c) 1998-2025 The OpenSSL Project Authors. All Rights Reserved. |
| [libsodium](https://libsodium.org/) | 1.0.20 | ISC | Copyright (c) 2013-2025 Frank Denis <j at pureftpd dot org> |
| [libsodium-cmake](https://github.com/robinlinden/libsodium-cmake) | efe978b | MIT | Copyright (c) 2019, Robin Linden |
| [Asio](https://think-async.com/Asio/) | 1.34.2 | BSL-1.0 | Copyright (c) 2003-2025 Christopher M. Kohlhoff |
| [spdlog (bundles fmt)](https://github.com/gabime/spdlog) | 1.16.0 | MIT | Copyright (c) 2016 Gabi Melman; fmt: Copyright (c) 2012-present Victor Zverovich and {fmt} contributors |
| [nlohmann/json](https://github.com/nlohmann/json) | 3.12.0 | MIT | Copyright (c) 2013-2025 Niels Lohmann |
| [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) | 0.7.0 | MIT | Copyright (c) 2018 Dominik Thalhammer |
| [magic_enum](https://github.com/Neargye/magic_enum) | 0.9.7 | MIT | Copyright (c) 2019-2024 Daniil Goncharov |
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) | 0.18.3 | MIT | Copyright (c) 2017 yhirose |
| [c-ares](https://c-ares.org/) | 1.34.6 | MIT | Copyright (c) 1998 Massachusetts Institute of Technology; Copyright (c) 2007-2023 Daniel Stenberg with many contributors |
| [xxHash](https://github.com/Cyan4973/xxHash) | 0.8.3 | BSD-2-Clause | Copyright (c) 2012-2021 Yann Collet |
| [SQLite](https://www.sqlite.org/) | 3.46.1 | Public domain | The SQLite authors have dedicated the code to the public domain. |
| [tpm2-tss (Linux only, FAPI/ESAPI)](https://github.com/tpm2-software/tpm2-tss) | 4.1.3 | BSD-2-Clause | Copyright (c) 2015-2018 Intel Corporation; Copyright (c) 2018-2024 Fraunhofer SIT and contributors |
| [json-c (Linux only, via tpm2-tss)](https://github.com/json-c/json-c) | system | MIT | Copyright (c) 2009-2012 Eric Haszlakiewicz; Copyright (c) 2004, 2005 Metaparadigm Pte Ltd |
| [libcurl (Linux only, via tpm2-tss)](https://curl.se/) | system | curl | Copyright (c) Daniel Stenberg, <daniel@haxx.se>, and many contributors |
| [libuuid (Linux only, via tpm2-tss)](https://github.com/util-linux/util-linux) | system | BSD-3-Clause | Copyright (c) 1996-2007 Theodore Ts'o |

## 2. Rust crates

Compiled into the `lemonade-boringtun-ffi` (WireGuard data plane) and
`lemonade-virtual-netstack` (userspace TCP/IP) static libraries, which are
linked into the server, sidecar, and client SDK. Where a crate is offered under
a choice of licenses, Lemonade-Nexus uses it under the MIT license if that is
one of the choices, otherwise under the first listed. Some crates (build
scripts and procedural macros such as `cc`, `syn`, `quote`) run only at build
time and are not present in shipped binaries; they are listed for completeness.

| Crate | Version | License | Copyright |
|---|---|---|---|
| [aead](https://github.com/RustCrypto/traits) | 0.5.2 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [autocfg](https://github.com/cuviper/autocfg) | 1.5.1 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [base64](https://github.com/marshallpierce/rust-base64) | 0.13.1 | MIT/Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [bitflags](https://github.com/bitflags/bitflags) | 1.3.2 | MIT/Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [bitflags](https://github.com/bitflags/bitflags) | 2.13.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [blake2](https://github.com/RustCrypto/hashes) | 0.10.6 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [block-buffer](https://github.com/RustCrypto/utils) | 0.10.4 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [boringtun](https://github.com/cloudflare/boringtun) | 0.6.0 | BSD-3-Clause | Copyright (c) 2019 Cloudflare, Inc. |
| [bumpalo](https://github.com/fitzgen/bumpalo) | 3.20.3 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [byteorder](https://github.com/BurntSushi/byteorder) | 1.5.0 | Unlicense OR MIT | Copyright (c) 2015 Andrew Gallant |
| [cc](https://github.com/rust-lang/cc-rs) | 1.2.65 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [cfg-if](https://github.com/rust-lang/cfg-if) | 1.0.4 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [chacha20](https://github.com/RustCrypto/stream-ciphers) | 0.9.1 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [chacha20poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) | 0.10.1 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [cipher](https://github.com/RustCrypto/traits) | 0.4.4 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [cpufeatures](https://github.com/RustCrypto/utils) | 0.2.17 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [crypto-common](https://github.com/RustCrypto/traits) | 0.1.7 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | 4.0.0-rc.3 | BSD-3-Clause | Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.; Copyright (c) 2016-2021 Henry de Valence. All rights reserved. |
| [curve25519-dalek-derive](https://github.com/dalek-cryptography/curve25519-dalek) | 0.1.1 | MIT/Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [defmt](https://github.com/knurling-rs/defmt) | 0.3.100 | MIT OR Apache-2.0 | Copyright (c) 2020 Ferrous Systems GmbH |
| [defmt](https://github.com/knurling-rs/defmt) | 1.1.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [defmt-macros](https://github.com/knurling-rs/defmt) | 1.1.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [defmt-parser](https://github.com/knurling-rs/defmt) | 1.0.0 | MIT OR Apache-2.0 | Copyright (c) 2020 Ferrous Systems GmbH |
| [digest](https://github.com/RustCrypto/traits) | 0.10.7 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [fiat-crypto](https://github.com/mit-plv/fiat-crypto) | 0.1.20 | MIT OR Apache-2.0 OR BSD-1-Clause | Copyright 2015-2020 the fiat-crypto authors (see the AUTHORS file) |
| [find-msvc-tools](https://github.com/rust-lang/cc-rs) | 0.1.9 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [generic-array](https://github.com/fizyk20/generic-array.git) | 0.14.7 | MIT | Copyright (c) 2015 Bartłomiej Kamiński |
| [getrandom](https://github.com/rust-random/getrandom) | 0.2.17 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [hash32](https://github.com/japaric/hash32) | 0.3.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [heapless](https://github.com/rust-embedded/heapless) | 0.8.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [hex](https://github.com/KokaKiwi/rust-hex) | 0.4.3 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [hmac](https://github.com/RustCrypto/MACs) | 0.12.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [inout](https://github.com/RustCrypto/utils) | 0.1.4 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [ip_network](https://github.com/JakubOnderka/ip_network) | 0.4.1 | BSD-2-Clause | Copyright (c) 2017, Jakub Onderka |
| [ip_network_table](https://github.com/JakubOnderka/ip_network_table) | 0.2.0 | BSD-2-Clause | Copyright (c) 2018, Jakub Onderka |
| [ip_network_table-deps-treebitmap](https://github.com/JakubOnderka/treebitmap) | 0.5.0 | MIT | Copyright (c) 2016 Hroi Sigurdsson |
| [js-sys](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) | 0.3.103 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [lazy_static](https://github.com/rust-lang-nursery/lazy-static.rs) | 1.5.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [libc](https://github.com/rust-lang/libc) | 0.2.186 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [lock_api](https://github.com/Amanieu/parking_lot) | 0.4.14 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [log](https://github.com/rust-lang/log) | 0.4.33 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [managed](https://github.com/m-labs/rust-managed.git) | 0.8.0 | 0BSD | Copyright (C) 2017 whitequark@whitequark.org |
| [mio](https://github.com/tokio-rs/mio) | 1.0.3 | MIT | Copyright (c) 2014 Carl Lerche and other MIO contributors |
| [nix](https://github.com/nix-rust/nix) | 0.25.1 | MIT | Copyright (c) 2015 Carl Lerche + nix-rust Authors |
| [nu-ansi-term](https://github.com/nushell/nu-ansi-term) | 0.50.3 | MIT | Copyright (c) 2014 Benjamin Sago; Copyright (c) 2021-2022 The Nushell Project Developers |
| [once_cell](https://github.com/matklad/once_cell) | 1.21.4 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [opaque-debug](https://github.com/RustCrypto/utils) | 0.3.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [parking_lot](https://github.com/Amanieu/parking_lot) | 0.12.5 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [parking_lot_core](https://github.com/Amanieu/parking_lot) | 0.9.12 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [pin-project-lite](https://github.com/taiki-e/pin-project-lite) | 0.2.17 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [platforms](https://github.com/rustsec/rustsec) | 3.12.0 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [poly1305](https://github.com/RustCrypto/universal-hashes) | 0.8.0 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [proc-macro-error-attr2](https://github.com/GnomedDev/proc-macro-error-2) | 2.0.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [proc-macro-error2](https://github.com/GnomedDev/proc-macro-error-2) | 2.0.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [proc-macro2](https://github.com/dtolnay/proc-macro2) | 1.0.106 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [quote](https://github.com/dtolnay/quote) | 1.0.46 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [rand_core](https://github.com/rust-random/rand) | 0.6.4 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [redox_syscall](https://gitlab.redox-os.org/redox-os/syscall) | 0.5.18 | MIT | Copyright (c) 2017 Redox OS Developers |
| [ring](https://github.com/briansmith/ring) | 0.16.20 | see crate LICENSE | Copyright 2015-2016 Brian Smith.; Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved. |
| [rustc_version](https://github.com/djc/rustc-version-rs) | 0.4.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [rustversion](https://github.com/dtolnay/rustversion) | 1.0.22 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [scopeguard](https://github.com/bluss/scopeguard) | 1.2.0 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [semver](https://github.com/dtolnay/semver) | 1.0.28 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [serde](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [serde_core](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [serde_derive](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [sharded-slab](https://github.com/hawkw/sharded-slab) | 0.1.7 | MIT | Copyright (c) 2019 Eliza Weisman |
| [shlex](https://github.com/comex/rust-shlex) | 2.0.1 | MIT OR Apache-2.0 | Copyright 2015 Nicholas Allegra (comex). |
| [smallvec](https://github.com/servo/rust-smallvec) | 1.15.2 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [smoltcp](https://github.com/smoltcp-rs/smoltcp.git) | 0.11.0 | 0BSD | Copyright (C) 2016 whitequark@whitequark.org |
| [spin](https://github.com/mvdnes/spin-rs.git) | 0.5.2 | MIT | Copyright (c) 2014 Mathijs van de Nes |
| [stable_deref_trait](https://github.com/storyyeller/stable_deref_trait) | 1.2.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [subtle](https://github.com/dalek-cryptography/subtle) | 2.6.1 | BSD-3-Clause | Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.; Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved. |
| [syn](https://github.com/dtolnay/syn) | 2.0.118 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [thiserror](https://github.com/dtolnay/thiserror) | 2.0.18 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [thiserror-impl](https://github.com/dtolnay/thiserror) | 2.0.18 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [thread_local](https://github.com/Amanieu/thread_local-rs) | 1.1.9 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [tracing](https://github.com/tokio-rs/tracing) | 0.1.44 | MIT | Copyright (c) 2019 Tokio Contributors |
| [tracing-attributes](https://github.com/tokio-rs/tracing) | 0.1.31 | MIT | Copyright (c) 2019 Tokio Contributors |
| [tracing-core](https://github.com/tokio-rs/tracing) | 0.1.36 | MIT | Copyright (c) 2019 Tokio Contributors |
| [tracing-log](https://github.com/tokio-rs/tracing) | 0.2.0 | MIT | Copyright (c) 2019 Tokio Contributors |
| [tracing-subscriber](https://github.com/tokio-rs/tracing) | 0.3.23 | MIT | Copyright (c) 2019 Tokio Contributors |
| [typenum](https://github.com/paholg/typenum) | 1.20.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [unicode-ident](https://github.com/dtolnay/unicode-ident) | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [universal-hash](https://github.com/RustCrypto/traits) | 0.5.1 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [untrusted](https://github.com/briansmith/untrusted) | 0.7.1 | ISC | Copyright 2015-2016 Brian Smith. |
| [untrusted](https://github.com/briansmith/untrusted) | 0.9.0 | ISC | Copyright 2015-2016 Brian Smith. |
| [valuable](https://github.com/tokio-rs/valuable) | 0.1.1 | MIT | Copyright (c) 2021 Tokio Contributors |
| [version_check](https://github.com/SergioBenitez/version_check) | 0.9.5 | MIT/Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [wasi](https://github.com/bytecodealliance/wasi) | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) | 0.2.126 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [wasm-bindgen-macro](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro) | 0.2.126 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [wasm-bindgen-macro-support](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support) | 0.2.126 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [wasm-bindgen-shared](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared) | 0.2.126 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [web-sys](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys) | 0.3.103 | MIT OR Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [winapi](https://github.com/retep998/winapi-rs) | 0.3.9 | MIT/Apache-2.0 | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [winapi-i686-pc-windows-gnu](https://github.com/retep998/winapi-rs) | 0.4.0 | MIT/Apache-2.0 | Copyright (c) 2015-2018 The winapi-rs Developers |
| [winapi-x86_64-pc-windows-gnu](https://github.com/retep998/winapi-rs) | 0.4.0 | MIT/Apache-2.0 | Copyright (c) 2015-2018 The winapi-rs Developers |
| [windows-link](https://github.com/microsoft/windows-rs) | 0.2.1 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows-sys](https://github.com/microsoft/windows-rs) | 0.52.0 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows-sys](https://github.com/microsoft/windows-rs) | 0.61.2 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows-targets](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_aarch64_gnullvm](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_aarch64_msvc](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_i686_gnu](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_i686_gnullvm](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_i686_msvc](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_x86_64_gnu](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_x86_64_gnullvm](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [windows_x86_64_msvc](https://github.com/microsoft/windows-rs) | 0.52.6 | MIT OR Apache-2.0 | Copyright (c) Microsoft Corporation |
| [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) | 2.0.0-rc.3 | BSD-3-Clause | Copyright (c) 2017-2021 isis agora lovecruft. All rights reserved.; Copyright (c) 2019-2021 DebugSteven. All rights reserved. |
| [zeroize](https://github.com/RustCrypto/utils) | 1.9.0 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |
| [zeroize_derive](https://github.com/RustCrypto/utils) | 1.5.0 | Apache-2.0 OR MIT | 2. Grant of Copyright License. Subject to the terms and conditions of; copyright license to reproduce, prepare Derivative Works of, |

## 3. Dart and Flutter packages (desktop client only)

The desktop client is built with Flutter. Flutter's build embeds the license
text of every Dart package below into the application bundle, and the client
exposes them, together with this file, through the in-app "Licenses" page.
The Flutter framework and engine are Copyright 2014 The Flutter Authors,
BSD-3-Clause.

| Package | Version | Dependency kind |
|---|---|---|
| _fe_analyzer_shared | 100.0.0 | transitive |
| analyzer | 13.0.0 | transitive |
| archive | 4.0.9 | transitive |
| args | 2.7.0 | transitive |
| async | 2.13.1 | transitive |
| boolean_selector | 2.1.2 | transitive |
| build | 4.0.6 | transitive |
| build_config | 1.3.0 | transitive |
| build_daemon | 4.1.1 | transitive |
| build_runner | 2.15.0 | direct dev |
| built_collection | 5.1.1 | transitive |
| built_value | 8.12.6 | transitive |
| characters | 1.4.1 | transitive |
| checked_yaml | 2.0.4 | transitive |
| cli_util | 0.5.1 | transitive |
| clock | 1.1.2 | transitive |
| code_assets | 1.2.1 | transitive |
| collection | 1.19.1 | transitive |
| console | 4.1.0 | transitive |
| convert | 3.1.2 | transitive |
| crypto | 3.0.7 | transitive |
| dart_style | 3.1.9 | transitive |
| fake_async | 1.3.3 | transitive |
| ffi | 2.2.0 | direct main |
| file | 7.0.1 | transitive |
| fixnum | 1.1.1 | transitive |
| flutter | 0.0.0 | direct main |
| flutter_lints | 6.0.0 | direct dev |
| flutter_riverpod | 2.6.1 | direct main |
| flutter_secure_storage | 9.2.4 | direct main |
| flutter_secure_storage_linux | 1.2.3 | transitive |
| flutter_secure_storage_macos | 3.1.3 | transitive |
| flutter_secure_storage_platform_interface | 1.1.2 | transitive |
| flutter_secure_storage_web | 1.2.1 | transitive |
| flutter_secure_storage_windows | 3.1.2 | transitive |
| flutter_test | 0.0.0 | direct dev |
| flutter_web_plugins | 0.0.0 | transitive |
| get_it | 9.2.1 | transitive |
| glob | 2.1.3 | transitive |
| graphs | 2.3.2 | transitive |
| hooks | 2.0.2 | transitive |
| http | 1.2.0 | direct main |
| http_multi_server | 3.2.2 | transitive |
| http_parser | 4.1.2 | transitive |
| image | 4.9.1 | transitive |
| io | 1.0.5 | transitive |
| jni | 1.0.0 | transitive |
| jni_flutter | 1.0.1 | transitive |
| js | 0.6.7 | transitive |
| json_annotation | 4.12.0 | direct main |
| json_serializable | 6.14.0 | direct dev |
| leak_tracker | 11.0.2 | transitive |
| leak_tracker_flutter_testing | 3.0.10 | transitive |
| leak_tracker_testing | 3.0.2 | transitive |
| lints | 6.1.0 | transitive |
| logging | 1.3.0 | transitive |
| matcher | 0.12.19 | transitive |
| material_color_utilities | 0.13.0 | transitive |
| menu_base | 0.1.1 | transitive |
| meta | 1.18.0 | transitive |
| mime | 2.0.0 | transitive |
| msix | 3.17.0 | direct dev |
| objective_c | 9.4.1 | transitive |
| package_config | 2.2.0 | transitive |
| path | 1.9.1 | direct main |
| path_provider | 2.1.6 | direct main |
| path_provider_android | 2.3.1 | transitive |
| path_provider_foundation | 2.6.0 | transitive |
| path_provider_linux | 2.2.2 | transitive |
| path_provider_platform_interface | 2.1.3 | transitive |
| path_provider_windows | 2.3.0 | transitive |
| petitparser | 7.0.2 | transitive |
| platform | 3.1.6 | transitive |
| plugin_platform_interface | 2.1.8 | transitive |
| pool | 1.5.2 | transitive |
| posix | 6.5.0 | transitive |
| pub_semver | 2.2.0 | transitive |
| pubspec_parse | 1.5.0 | transitive |
| record_use | 0.6.0 | transitive |
| riverpod | 2.6.1 | transitive |
| screen_retriever | 0.2.1 | transitive |
| screen_retriever_linux | 0.2.1 | transitive |
| screen_retriever_macos | 0.2.1 | transitive |
| screen_retriever_platform_interface | 0.2.1 | transitive |
| screen_retriever_windows | 0.2.1 | transitive |
| shared_preferences | 2.2.3 | direct main |
| shared_preferences_android | 2.4.26 | transitive |
| shared_preferences_foundation | 2.5.6 | transitive |
| shared_preferences_linux | 2.4.1 | transitive |
| shared_preferences_platform_interface | 2.4.2 | transitive |
| shared_preferences_web | 2.2.2 | transitive |
| shared_preferences_windows | 2.4.1 | transitive |
| shelf | 1.4.2 | transitive |
| shelf_web_socket | 3.0.0 | transitive |
| shortid | 0.1.2 | transitive |
| sky_engine | 0.0.0 | transitive |
| source_gen | 4.2.3 | transitive |
| source_helper | 1.3.12 | transitive |
| source_span | 1.10.2 | transitive |
| stack_trace | 1.12.1 | transitive |
| state_notifier | 1.0.0 | transitive |
| stream_channel | 2.1.4 | transitive |
| stream_transform | 2.1.1 | transitive |
| string_scanner | 1.4.1 | transitive |
| term_glyph | 1.2.2 | transitive |
| test_api | 0.7.11 | transitive |
| tray_manager | 0.2.4 | direct main |
| typed_data | 1.4.0 | transitive |
| vector_math | 2.2.0 | transitive |
| vm_service | 15.2.0 | transitive |
| watcher | 1.2.1 | transitive |
| web | 0.4.2 | transitive |
| web_socket_channel | 2.4.3 | direct main |
| win32 | 5.15.0 | direct main |
| win32_registry | 1.1.5 | direct main |
| window_manager | 0.4.3 | direct main |
| xdg_directories | 1.1.0 | transitive |
| xml | 7.0.1 | transitive |
| yaml | 3.1.3 | transitive |

## 4. Flutter template code

The platform runner sources under `apps/LemonadeNexusClient/windows/runner/`,
`macos/Runner/`, and `linux/runner/` are derived from the Flutter project
templates and remain under Flutter's BSD-3-Clause license. Copyright 2014
The Flutter Authors. All rights reserved. The license text is in
`apps/LemonadeNexusClient/windows/runner/LICENSE` and reproduced below.
These files are Third-Party Components for the purposes of the
Lemonade-Nexus license.

## 5. Build and test tools (not distributed)

| Component | Version | License | Copyright |
|---|---|---|---|
| [GoogleTest](https://github.com/google/googletest) | 1.15.2 | BSD-3-Clause | Copyright 2008, Google Inc. |
| [Corrosion](https://github.com/corrosion-rs/corrosion) | (FetchContent) | MIT | Copyright (c) 2018 Andrew Gaspar |

## License texts

---

### Apache License 2.0 (OpenSSL and Apache-2.0 crates)

```
                              Apache License
                        Version 2.0, January 2004
                     http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

   "License" shall mean the terms and conditions for use, reproduction,
   and distribution as defined by Sections 1 through 9 of this document.

   "Licensor" shall mean the copyright owner or entity authorized by
   the copyright owner that is granting the License.

   "Legal Entity" shall mean the union of the acting entity and all
   other entities that control, are controlled by, or are under common
   control with that entity. For the purposes of this definition,
   "control" means (i) the power, direct or indirect, to cause the
   direction or management of such entity, whether by contract or
   otherwise, or (ii) ownership of fifty percent (50%) or more of the
   outstanding shares, or (iii) beneficial ownership of such entity.

   "You" (or "Your") shall mean an individual or Legal Entity
   exercising permissions granted by this License.

   "Source" form shall mean the preferred form for making modifications,
   including but not limited to software source code, documentation
   source, and configuration files.

   "Object" form shall mean any form resulting from mechanical
   transformation or translation of a Source form, including but
   not limited to compiled object code, generated documentation,
   and conversions to other media types.

   "Work" shall mean the work of authorship, whether in Source or
   Object form, made available under the License, as indicated by a
   copyright notice that is included in or attached to the work
   (an example is provided in the Appendix below).

   "Derivative Works" shall mean any work, whether in Source or Object
   form, that is based on (or derived from) the Work and for which the
   editorial revisions, annotations, elaborations, or other modifications
   represent, as a whole, an original work of authorship. For the purposes
   of this License, Derivative Works shall not include works that remain
   separable from, or merely link (or bind by name) to the interfaces of,
   the Work and Derivative Works thereof.

   "Contribution" shall mean any work of authorship, including
   the original version of the Work and any modifications or additions
   to that Work or Derivative Works thereof, that is intentionally
   submitted to Licensor for inclusion in the Work by the copyright owner
   or by an individual or Legal Entity authorized to submit on behalf of
   the copyright owner. For the purposes of this definition, "submitted"
   means any form of electronic, verbal, or written communication sent
   to the Licensor or its representatives, including but not limited to
   communication on electronic mailing lists, source code control systems,
   and issue tracking systems that are managed by, or on behalf of, the
   Licensor for the purpose of discussing and improving the Work, but
   excluding communication that is conspicuously marked or otherwise
   designated in writing by the copyright owner as "Not a Contribution."

   "Contributor" shall mean Licensor and any individual or Legal Entity
   on behalf of whom a Contribution has been received by Licensor and
   subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and conditions of
   this License, each Contributor hereby grants to You a perpetual,
   worldwide, non-exclusive, no-charge, royalty-free, irrevocable
   copyright license to reproduce, prepare Derivative Works of,
   publicly display, publicly perform, sublicense, and distribute the
   Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of
   this License, each Contributor hereby grants to You a perpetual,
   worldwide, non-exclusive, no-charge, royalty-free, irrevocable
   (except as stated in this section) patent license to make, have made,
   use, offer to sell, sell, import, and otherwise transfer the Work,
   where such license applies only to those patent claims licensable
   by such Contributor that are necessarily infringed by their
   Contribution(s) alone or by combination of their Contribution(s)
   with the Work to which such Contribution(s) was submitted. If You
   institute patent litigation against any entity (including a
   cross-claim or counterclaim in a lawsuit) alleging that the Work
   or a Contribution incorporated within the Work constitutes direct
   or contributory patent infringement, then any patent licenses
   granted to You under this License for that Work shall terminate
   as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of the
   Work or Derivative Works thereof in any medium, with or without
   modifications, and in Source or Object form, provided that You
   meet the following conditions:

   (a) You must give any other recipients of the Work or
       Derivative Works a copy of this License; and

   (b) You must cause any modified files to carry prominent notices
       stating that You changed the files; and

   (c) You must retain, in the Source form of any Derivative Works
       that You distribute, all copyright, patent, trademark, and
       attribution notices from the Source form of the Work,
       excluding those notices that do not pertain to any part of
       the Derivative Works; and

   (d) If the Work includes a "NOTICE" text file as part of its
       distribution, then any Derivative Works that You distribute must
       include a readable copy of the attribution notices contained
       within such NOTICE file, excluding those notices that do not
       pertain to any part of the Derivative Works, in at least one
       of the following places: within a NOTICE text file distributed
       as part of the Derivative Works; within the Source form or
       documentation, if provided along with the Derivative Works; or,
       within a display generated by the Derivative Works, if and
       wherever such third-party notices normally appear. The contents
       of the NOTICE file are for informational purposes only and
       do not modify the License. You may add Your own attribution
       notices within Derivative Works that You distribute, alongside
       or as an addendum to the NOTICE text from the Work, provided
       that such additional attribution notices cannot be construed
       as modifying the License.

   You may add Your own copyright statement to Your modifications and
   may provide additional or different license terms and conditions
   for use, reproduction, or distribution of Your modifications, or
   for any such Derivative Works as a whole, provided Your use,
   reproduction, and distribution of the Work otherwise complies with
   the conditions stated in this License.

5. Submission of Contributions. Unless You explicitly state otherwise,
   any Contribution intentionally submitted for inclusion in the Work
   by You to the Licensor shall be under the terms and conditions of
   this License, without any additional terms or conditions.
   Notwithstanding the above, nothing herein shall supersede or modify
   the terms of any separate license agreement you may have executed
   with Licensor regarding such Contributions.

6. Trademarks. This License does not grant permission to use the trade
   names, trademarks, service marks, or product names of the Licensor,
   except as required for reasonable and customary use in describing the
   origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or
   agreed to in writing, Licensor provides the Work (and each
   Contributor provides its Contributions) on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied, including, without limitation, any warranties or conditions
   of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
   PARTICULAR PURPOSE. You are solely responsible for determining the
   appropriateness of using or redistributing the Work and assume any
   risks associated with Your exercise of permissions under this License.

8. Limitation of Liability. In no event and under no legal theory,
   whether in tort (including negligence), contract, or otherwise,
   unless required by applicable law (such as deliberate and grossly
   negligent acts) or agreed to in writing, shall any Contributor be
   liable to You for damages, including any direct, indirect, special,
   incidental, or consequential damages of any character arising as a
   result of this License or out of the use or inability to use the
   Work (including but not limited to damages for loss of goodwill,
   work stoppage, computer failure or malfunction, or any and all
   other commercial damages or losses), even if such Contributor
   has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability. While redistributing
   the Work or Derivative Works thereof, You may choose to offer,
   and charge a fee for, acceptance of support, warranty, indemnity,
   or other liability obligations and/or rights consistent with this
   License. However, in accepting such obligations, You may act only
   on Your own behalf and on Your sole responsibility, not on behalf
   of any other Contributor, and only if You agree to indemnify,
   defend, and hold each Contributor harmless for any liability
   incurred by, or claims asserted against, such Contributor by reason
   of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS
```

---

### MIT License (spdlog, fmt, nlohmann/json, jwt-cpp, magic_enum, cpp-httplib, c-ares, json-c, libsodium-cmake, MIT crates)

```
Copyright (c) 2014 Carl Lerche and other MIO contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

### BSD 3-Clause License (boringtun, curve25519-dalek, x25519-dalek, subtle, Flutter, libuuid)

```
Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
Copyright (c) 2016-2021 Henry de Valence. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

========================================================================

Portions of curve25519-dalek were originally derived from Adam Langley's
Go ed25519 implementation, found at <https://github.com/agl/ed25519/>,
under the following licence:

========================================================================

Copyright (c) 2012 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

### BSD 2-Clause License (xxHash, tpm2-tss, ip_network)

```
Copyright (c) 2017, Jakub Onderka

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

### ISC License (libsodium, untrusted)

```
/*
 * ISC License
 *
 * Copyright (c) 2013-2026
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
```

---

### Boost Software License 1.0 (Asio)

```
Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

---

### Zero-Clause BSD (smoltcp, managed)

```
Copyright (C) 2016 whitequark@whitequark.org

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

---

### Unicode License v3 (unicode-ident data tables)

```
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2023 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

---

### curl License (libcurl)

```
Copyright (c) 1996 - 2025, Daniel Stenberg, <daniel@haxx.se>, and many
contributors, see the THANKS file.

All rights reserved.

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall not
be used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization of the copyright holder.
```

---

### SQLite (public domain)

```
The author disclaims copyright to this source code.  In place of
a legal notice, here is a blessing:

   May you do good and not evil.
   May you find forgiveness for yourself and forgive others.
   May you share freely, never taking more than you give.
```

---

### ring (ISC-style, BoringSSL, and OpenSSL/SSLeay terms)

```
Note that it is easy for this file to get out of sync with the licenses in the
source code files. It's recommended to compare the licenses in the source code
with what's mentioned here.

*ring* is derived from BoringSSL, so the licensing situation in *ring* is
similar to BoringSSL.

*ring* uses an ISC-style license like BoringSSL for code in new files,
including in particular all the Rust code:

   Copyright 2015-2016 Brian Smith.

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
   OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
   CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

BoringSSL is a fork of OpenSSL. As such, large parts of it fall under OpenSSL
licensing. Files that are completely new have a Google copyright and an ISC
license. This license is reproduced at the bottom of this file.

Contributors to BoringSSL are required to follow the CLA rules for Chromium:
https://cla.developers.google.com/clas

Files in third_party/ have their own licenses, as described therein. The MIT
license, for third_party/fiat, which, unlike other third_party directories, is
compiled into non-test libraries, is included below.

The OpenSSL toolkit stays under a dual license, i.e. both the conditions of the
OpenSSL License and the original SSLeay license apply to the toolkit. See below
for the actual license texts. Actually both licenses are BSD-style Open Source
licenses. In case of any license issues related to OpenSSL please contact
openssl-core@openssl.org.

The following are Google-internal bug numbers where explicit permission from
some authors is recorded for use of their work:
  27287199
  27287880
  27287883

  OpenSSL License
  ---------------

/* ====================================================================
 * Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

 Original SSLeay License
 -----------------------

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


ISC license used for completely new code in BoringSSL:

/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */


The code in third_party/fiat carries the MIT license:

Copyright (c) 2015-2016 the fiat-crypto authors (see
https://github.com/mit-plv/fiat-crypto/blob/master/AUTHORS).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
