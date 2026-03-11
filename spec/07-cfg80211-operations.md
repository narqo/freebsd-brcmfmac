# cfg80211 Operations

## Overview

The cfg80211 layer implements the wireless configuration API for FullMAC. Every operation translates high-level requests from the wireless stack into firmware commands via FWIL. The driver does not construct or parse 802.11 frames for data or management on the STA/AP data path — firmware handles all MAC-layer processing.

## Supported operations

| Operation | cfg80211 callback | Summary |
|-----------|-------------------|---------|
| Scan | `scan` | Enhanced scan (escan) via firmware |
| Connect | `connect` | Association via extended join or SET_SSID |
| Disconnect | `disconnect` | Disassociate from AP |
| Add key | `add_key` | Install pairwise or group key |
| Del key | `del_key` | Remove a key |
| Get key | `get_key` | Retrieve key info |
| Set default key | `set_default_key` | Set TX default key index |
| Set default mgmt key | `set_default_mgmt_key` | Set management frame key |
| Set power mgmt | `set_power_mgmt` | Enable/disable firmware PM |
| Get station | `get_station` | Query per-STA statistics |
| Set wiphy params | `set_wiphy_params` | RTS/frag threshold, retry counts |
| Start AP | `start_ap` | Configure and enable AP mode |
| Stop AP | `stop_ap` | Disable AP mode |
| Change beacon | `change_beacon` | Update AP beacon IEs |
| Del station | `del_station` | Deauthenticate a client (AP) |
| Change station | `change_station` | Authorize/deauthorize client (AP) |
| Set PMKSA | `set_pmksa` | Cache a PMKID |
| Del PMKSA | `del_pmksa` | Remove a cached PMKID |
| Flush PMKSA | `flush_pmksa` | Clear all cached PMKIDs |
| Sched scan start/stop | `sched_scan_*` | PNO (preferred network offload) |
| Mgmt TX | `mgmt_tx` | Transmit action frame |
| Remain on channel | `remain_on_channel` | Off-channel dwell (P2P) |
| TDLS oper | `tdls_oper` | TDLS setup/teardown |
| Set PMK | `set_pmk` | Install PMK directly |
| Del PMK | `del_pmk` | Remove PMK |
| CQM RSSI config | `set_cqm_rssi_range_config` | RSSI threshold monitoring |
| Update connect params | `update_connect_params` | Update IEs for reassoc |

## Scanning

### Enhanced scan (escan)

The driver uses the enhanced scan mechanism exclusively. This delivers incremental results via firmware events rather than blocking until complete.

#### Scan request

1. Disable MPC (Minimum Power Consumption) during scan if the `NEED_MPC` quirk is set.
2. Build escan parameters:
   - Version: 1 or 2 (if `SCAN_V2` feature detected).
   - Action: `WL_ESCAN_ACTION_START` (1).
   - Sync ID: random 16-bit value.
   - SSID list from the scan request (up to 10 SSIDs in the SSID array, encoded after the channel list).
   - Channel list: converted from `ieee80211_channel` to Broadcom chanspecs.
   - Scan type per channel: active or passive based on channel flags.
3. Send via `brcmf_fil_iovar_data_set(ifp, "escan", params, params_size)`.
4. If the IOVAR fails, complete the scan with `aborted = true`.
5. Start a 10-second timer for scan timeout.

#### Scan results (event-driven)

Results arrive as `BRCMF_E_ESCAN_RESULT` events:
- Status `PARTIAL` (8): Contains one or more BSS info entries. Each is validated and merged into a host-side buffer (`escan_buf`, 65000 bytes). Duplicate BSSIDs are updated in place (newer data replaces older).
- Status `SUCCESS` (0) or `ABORT` (4): Scan complete. The host walks the buffer, reports each BSS to cfg80211 via `cfg80211_inform_bss`, then completes the scan request.

#### BSS info conversion

Each `brcmf_bss_info_le` from firmware contains:
- BSSID, SSID, RSSI, noise floor
- Beacon period, capability, DTIM period
- Chanspec (converted to an `ieee80211_channel`)
- IEs (starting at `ie_offset` from the structure start)

The host constructs `cfg80211_inform_bss_data` with signal type `MBM` (RSSI × 100).

#### Scan abort

To abort a running scan: send an escan with `action = WL_ESCAN_ACTION_ABORT` and the same sync ID.

## Connection (STA mode)

### Connect flow

1. **Check state**: Reject if VIF is not up.
2. **Security setup** (in order):
   a. `brcmf_set_wpa_version`: Set `wpa_auth` IOVAR to WPA/WPA2/WPA3 bitmask.
   b. `brcmf_set_auth_type`: Set `auth` command based on authentication algorithm (open, shared, SAE).
   c. `brcmf_set_wsec_mode`: Set `wsec` to cipher bitmask (WEP, TKIP, AES, etc.).
   d. `brcmf_set_key_mgmt`: Set `wpa_auth` IOVAR for key management suite (PSK, 802.1X, SAE, FT variants).
   e. `brcmf_set_sharedkey`: For WEP shared-key auth, install the key and set auth type to 1.
3. **Firmware supplicant**:
   - For PSK: set `sup_wpa = 1`, then install PMK via `C_SET_WSEC_PMK`.
   - For SAE: set `sup_wpa = 1`, install SAE password, optionally install PMK.
   - For 802.1X: firmware supplicant not used.
4. **WPA IE**: Push the WPA/RSN IE from the connect request to firmware via `wpaie` IOVAR.
5. **Association IEs**: Set vendor IEs for association request.
6. **Join preference**: Configure band and RSSI preferences via `join_pref` IOVAR.
7. **Extended join**: First attempt uses `brcmf_fil_bsscfg_data_set(ifp, "join", ...)` with:
   - SSID
   - Scan parameters (type, dwell times, probe count)
   - BSSID (or broadcast)
   - Chanspec (if channel known)
8. **Fallback**: If extended join fails, fall back to `BRCMF_C_SET_SSID` with basic join parameters.
9. Set `CONNECTING` VIF status bit. Clear it on error.

### Connection result events

Connection success/failure is determined by firmware events (see [06-event-handling.md](06-event-handling.md)):
- `SET_SSID` with `SUCCESS` → association succeeded
- `PSK_SUP` with `FWSUP_COMPLETED` → 4-way handshake succeeded (when using firmware supplicant)
- Both conditions must be met when firmware supplicant is active

On success:
1. Retrieve BSS info from firmware.
2. Retrieve association request/response IEs from firmware via `assoc_info` / `assoc_resp_ies` IOVARs.
3. Report to cfg80211 via `cfg80211_connect_result`.
4. Set `CONNECTED` and clear `CONNECTING` VIF status.
5. Enable carrier on the network device.

### Disconnect

1. Clear `CONNECTED` and `CONNECTING` status.
2. Send `BRCMF_C_DISASSOC` with the BSSID and reason code.
3. Report to cfg80211 via `cfg80211_disconnected`.
4. Disable carrier.
5. Re-enable MPC.

### Link down (event-driven)

When firmware signals link-down (DEAUTH, DEAUTH_IND, DISASSOC_IND, or LINK with no link flag):
1. Check if still connected.
2. Map the firmware event to an 802.11 reason code.
3. Report disconnection to cfg80211.
4. Clear connection profile.

## Key management

### Add key

Maps cipher suites to firmware algorithm codes:

| cfg80211 cipher | Firmware algo |
|----------------|---------------|
| WEP40 | CRYPTO_ALGO_WEP1 |
| WEP104 | CRYPTO_ALGO_WEP128 |
| TKIP | CRYPTO_ALGO_TKIP |
| CCMP-128 | CRYPTO_ALGO_AES_CCM |
| AES-CMAC | CRYPTO_ALGO_AES_CCM (with PRIMARY flag) |

Key installation:
1. Build a `brcmf_wsec_key_le` structure with index, length, data, algorithm, and flags.
2. Convert all fields to little-endian.
3. For pairwise keys: set the peer MAC address. For group keys: set the `PRIMARY` flag if this is the default TX key.
4. Send via `wsec_key` IOVAR.

### Set default key

Sends the key with the `PRIMARY` flag set to firmware.

## AP mode

### Start AP

1. Set interface type to AP.
2. Configure SSID, beacon interval, DTIM period.
3. Set security: `wsec`, `wpa_auth`, `mfp`, and optionally install pre-shared key.
4. Set channel via chanspec.
5. Configure WMM/QoS parameters (EDCF AC parameters).
6. Set vendor IEs for beacon, probe response, and association response.
7. Set `closednet` IOVAR for hidden SSID.
8. Set `infra = 1`, `ap = 1`.
9. Bring BSS up via `bss` IOVAR.
10. Set beacon timeout, rate, and DTIM.
11. Set `AP_CREATED` VIF status.

### Stop AP

1. Disable BSS via `bss` IOVAR with `enable = 0`.
2. Set `ap = 0`, `mpc = 1`.
3. Clear `AP_CREATED` VIF status.
4. Clear vendor IEs.

### Client management (AP mode)

- **Del station**: Send `BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON` with the client's MAC and reason code.
- **Change station**: Send `BRCMF_C_SET_SCB_AUTHORIZE` or `BRCMF_C_SET_SCB_DEAUTHORIZE` based on the station flags.

## Power management

`set_power_mgmt` sends `BRCMF_C_SET_PM` with:
- 0: PM disabled
- 1: PM enabled (firmware manages sleep)
- 2: Fast PM (not used by cfg80211 path)

## Station info

`get_station` queries firmware for:
- **STA mode**: RSSI via `BRCMF_C_GET_RSSI`, rate via `BRCMF_C_GET_RATE`, BSS info for signal/noise.
- **AP mode**: Per-client stats via `sta_info` IOVAR, which returns a versioned structure with TX/RX counters.

## RSSI monitoring (CQM)

The driver uses firmware RSSI event monitoring:
1. Configure low and high RSSI thresholds on the VIF.
2. Set the `rssi_event` IOVAR with the threshold values.
3. Firmware sends `BRCMF_E_RSSI` events when thresholds are crossed.
4. The event handler compares the new RSSI against thresholds and reports to cfg80211.

## Feature detection

Features are detected by querying firmware capabilities:

1. Read `cap` IOVAR to get a space-separated capability string.
2. Match known capability tokens (e.g., `"mbss"`, `"p2p"`, `"sae "`, `"monitor"`, `"rtap"`, `"idauth"`).
3. Probe specific IOVARs to detect support:
   - `tdls_enable` → TDLS
   - `pfn` → PNO
   - `wnm` → WOWL
   - `mfp` → MFP (802.11w)
   - `sup_wpa` → firmware supplicant (FWSUP)
   - `scan_ver` → scan version 2

Features and quirks influence:
- Which cfg80211 operations are registered
- Which cipher suites are advertised
- Which interface types are supported
- Scan parameter encoding version
