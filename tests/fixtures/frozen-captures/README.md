# Frozen capture manifests for the tests

`tests/helpers.py` `frozen_archive()` builds the test archive from these manifests, not from
the live `captures/` folders. A day's `MANIFEST.json` can change after the fact, because later
capture runs append notes to it. (The 2026-11-23 capture appended diagnostic notes to the
2026-11-08 manifest, which changed what the tests saw.)

The raw files each manifest names are written once and never change. `frozen_archive()`
copies them from the live folders and checks each against the SHA-256 in the frozen manifest.

All files here are real records, copied exactly (nothing invented or edited):
- `captures/2026/11/08/MANIFEST.json`: as committed by the capture of 2026-11-11 (commit
  20ca99c), before the notes of 2026-11-23. It is identical to
  `tests/fixtures/ia-stored-copy/captures/2026/11/08/MANIFEST.json`.
- `captures/2026/10/30/MANIFEST.json` and the three `captures/anthropic-archive/*/MANIFEST.json`:
  as on main on 2026-11-23.

| File | SHA-256 |
|---|---|
| `captures/2026/10/30/MANIFEST.json` | `c5dac089a6e32f180edb61f1d9d142ca696c925662be095626c53a569a328bfc` |
| `captures/2026/11/08/MANIFEST.json` | `cdd55d1c262af6843fd37a2895703b204e811e4579a44448d6ad30dae83bd9cb` |
| `captures/anthropic-archive/2026-05-22-1027/MANIFEST.json` | `c457c1a0f126f057c33b6556fdae9569c5c8dcaef4753d1f07840eaad34826f9` |
| `captures/anthropic-archive/2026-08-26-1155/MANIFEST.json` | `14e7a2d9133d8f91b25cad1907d4f71848a86f1a61ad4b0422eaab9e0fc8e38a` |
| `captures/anthropic-archive/2026-10-02-1947/MANIFEST.json` | `ec02a962c2629a53bcf8bb7edcd4d607ed399ee5acc598a336b3d6dbf65c718f` |
