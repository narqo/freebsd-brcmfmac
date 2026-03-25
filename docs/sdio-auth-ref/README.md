# SDIO authentication blocker documentation

This directory contains clean-room documentation for the Linux brcmfmac SDIO path, focused on the pieces that matter to the RPi4/CYW43455 authentication blocker.

Files:
- `01-sdio-bus-and-runtime.md` — SDIO transport, mailbox handling, credits, DPC, control/data paths
- `02-bcdc-fws-and-association.md` — BCDC, firmware signalling, join/association flow, event handling, and blocker analysis

These documents describe behavior and interfaces without requiring access to the Linux source tree.
