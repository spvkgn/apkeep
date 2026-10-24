# Local terminal-cancellation patch

Upstream: crates.io `rpassword` **7.5.4**, copied from the Cargo registry cache.
The original source, Cargo metadata and Apache-2.0 license file are preserved.
No author attribution is replaced. See the original `Cargo.toml` and licenses.

Changed runtime behavior is limited to `RawModeInput::send_signal_sigint` on Unix:
restore the saved input and output termios with checked `tcsetattr` **before**
raising SIGINT. A default SIGINT may terminate the process before `Drop` runs;
upstream called `raise` first, leaving ECHO/ICANON/ISIG disabled on ordinary Ctrl-C.
Normal return/EOF cleanup remains owned by the original Drop implementation.
If restoration fails, return an I/O error rather than deliberately raising first.

The application-level regression uses a real isolated PTY, sends Ctrl-C only
after no-echo is active, and requires full termios restoration before signal exit.
Ctrl-D and invalid-token normal-return paths are also exercised. No Google login
or real token is used. See `tests/test_credentials_terminal.py`.

This is a root `[patch.crates-io]` source-checkout dependency patch, not a claim
that crates.io `rpassword` was modified/published or that Windows signal/console
semantics were verified. Preserve this entire directory and licenses in source
archives; registry publication needs a separate dependency strategy.
