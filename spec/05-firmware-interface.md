# Firmware Interface Layer (FWIL)

## Overview

FWIL provides the host API for sending commands and named variables to firmware. It operates on top of the protocol layer (msgbuf or BCDC), which handles the actual transport. FWIL is bus-independent.

All FWIL operations are serialized by a per-device mutex (`proto_block`). A single `proto_buf` (8192 bytes) is used as the wire buffer.

## Command model

Firmware supports two communication mechanisms:

1. **Direct commands** (`dcmd`): Identified by a numeric command code. Sent via `BRCMF_C_*` constants.
2. **IOVARs** (I/O variables): Named variables, accessed via the special commands `BRCMF_C_GET_VAR` (262) and `BRCMF_C_SET_VAR` (263). The variable name (NUL-terminated) is prepended to the payload.

### Command encoding

A direct command carries:
- Command code (integer)
- Payload buffer (variable length, capped at `BRCMF_DCMD_MAXLEN = 8192`)
- Direction: set (write) or get (read)
- Interface index

### IOVAR encoding

An IOVAR request is encoded as:

```
[name_string\0][data_bytes...]
```

Total length is `strlen(name) + 1 + data_len`. This blob is sent as payload to `BRCMF_C_SET_VAR` (for set) or `BRCMF_C_GET_VAR` (for get).

For get operations, the response data overwrites the `proto_buf` and is copied back to the caller's buffer.

### BSS-config IOVAR encoding

When the BSS config index is non-zero, an IOVAR is prefixed differently:

```
"bsscfg:"[name_string\0][bsscfgidx_le32][data_bytes...]
```

The `"bsscfg:"` prefix (7 bytes) is copied without a NUL terminator between it and the variable name. The variable name itself is NUL-terminated.

For `bsscfgidx == 0`, the encoding falls back to the simple IOVAR format.

### XTLV IOVAR encoding

Some newer IOVARs use extended TLV encoding:

```
[name_string\0][xtlv_header][data_bytes...]
```

The XTLV header contains a 16-bit type ID, 16-bit length, and data, with 32-bit alignment padding.

## Convenience functions

FWIL provides type-safe wrappers:

| Function | Description |
|----------|-------------|
| `fil_cmd_data_set(ifp, cmd, data, len)` | Send a direct set command |
| `fil_cmd_data_get(ifp, cmd, data, len)` | Send a direct get command |
| `fil_cmd_int_set(ifp, cmd, val)` | Set a 32-bit LE integer via direct command |
| `fil_cmd_int_get(ifp, cmd, &val)` | Get a 32-bit LE integer via direct command |
| `fil_iovar_data_set(ifp, name, data, len)` | Set an IOVAR |
| `fil_iovar_data_get(ifp, name, data, len)` | Get an IOVAR |
| `fil_iovar_int_set(ifp, name, val)` | Set a 32-bit LE integer IOVAR |
| `fil_iovar_int_get(ifp, name, &val)` | Get a 32-bit LE integer IOVAR |
| `fil_bsscfg_data_set(ifp, name, data, len)` | Set a BSS-config IOVAR |
| `fil_bsscfg_data_get(ifp, name, data, len)` | Get a BSS-config IOVAR |
| `fil_bsscfg_int_set(ifp, name, val)` | Set a 32-bit BSS-config IOVAR |
| `fil_xtlv_data_set(ifp, name, id, data, len)` | Set an XTLV IOVAR |
| `fil_xtlv_data_get(ifp, name, id, data, len)` | Get an XTLV IOVAR |

All integer values are converted to/from little-endian at the FWIL boundary.

## Error handling

When the transport returns success but firmware sets an error status:
- `fwerr` is a negative BCME error code
- FWIL translates this to `-EBADE` by default

An interface can opt into raw firmware error reporting by setting `ifp->fwil_fwerr = true`. When set, the function returns `fwerr` unconditionally, regardless of the transport error. This means if the transport failed (`err != 0`) but `fwerr == 0`, the function returns 0 (success), masking the transport error.

### Firmware error codes (BCME)

| Code | Name |
|------|------|
| 0 | BCME_OK |
| -1 | BCME_ERROR |
| -2 | BCME_BADARG |
| -3 | BCME_BADOPTION |
| -4 | BCME_NOTUP |
| -5 | BCME_NOTDOWN |
| -11 | BCME_NOCLK |
| -15 | BCME_BUFTOOLONG |
| -16 | BCME_BUSY |
| -17 | BCME_NOTASSOCIATED |
| -23 | BCME_UNSUPPORTED |
| -27 | BCME_NOMEM |
| -28 | BCME_ASSOCIATED |
| -29 | BCME_RANGE |
| -30 | BCME_NOTFOUND |

The complete list maps sequentially from 0 to -52.

## Bus state check

All FWIL operations check that `bus_if->state == BRCMF_BUS_UP` before proceeding. If the bus is down, they return `-EIO` immediately.

## Key firmware command codes

| Code | Name | Purpose |
|------|------|---------|
| 2 | `C_UP` | Bring interface up |
| 3 | `C_DOWN` | Bring interface down |
| 20 | `C_SET_INFRA` | Set infrastructure mode |
| 22 | `C_SET_AUTH` | Set authentication mode |
| 26 | `C_SET_SSID` | Associate to SSID |
| 45 | `C_SET_KEY` | Install a key |
| 50 | `C_SCAN` | Initiate scan |
| 52 | `C_DISASSOC` | Disassociate |
| 84 | `C_SET_COUNTRY` | Set country code |
| 86 | `C_SET_PM` | Set power management mode |
| 118 | `C_SET_AP` | Enable/disable AP mode |
| 127 | `C_GET_RSSI` | Get current RSSI |
| 134 | `C_SET_WSEC` | Set wireless security mode |
| 262 | `C_GET_VAR` | Get named variable |
| 263 | `C_SET_VAR` | Set named variable |
| 268 | `C_SET_WSEC_PMK` | Set PMK for WPA |

See [A1-firmware-commands.md](A1-firmware-commands.md) for the complete reference.
