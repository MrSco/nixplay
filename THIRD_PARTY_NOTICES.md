# Third-Party Notices

NixPlay is licensed under the GNU General Public License v3.0 or later (see `LICENSE`).
It contains code ported from the following projects.

## doubletake

- Project: https://github.com/omarroth/doubletake
- License: GNU Lesser General Public License v3.0 or later
- Used in: `src/airplay/fairplay/` (FairPlay SAP sender handshake and stream-key
  derivation, ported from Go to Rust) and `src/airplay/mirror.rs` (AirPlay screen
  mirroring session flow, frame header layout and encryption scheme).

LGPL-3.0-or-later code may be conveyed under the terms of the GPL-3.0-or-later
(LGPL-3.0 section 2), which is how it is distributed as part of NixPlay.
NixPlay contains no Apple source code or key material.
