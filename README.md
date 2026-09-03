# 80211fox

**find access points by signal**

A small Linux TUI for physically locating a Wi-Fi access point by SSID/BSSID,
RSSI, channel locking, and proximity beeps. It leaves unrelated Wi-Fi PHYs alone.

## Design and backend choice

The MVP uses only Python's standard library plus common distribution packages:

- **`iw`/nl80211** creates the monitor interface and tunes it. Frequencies and
  primary channel numbers come from `iw phy … info`, so the kernel's current
  regulatory view is authoritative; there is no hard-coded channel list.
- **TShark** captures passively and emits selected, tab-separated Wireshark
  fields. SCAN uses beacon/probe-response frames; after a BSSID is selected,
  HUNT also uses data frames transmitted by that AP for denser RSSI updates,
  while excluding uplink frames from clients. This avoids a home-grown
  radiotap/802.11 parser, Python packet dependencies, and Kali-specific tools.
  Capture is separate from the TUI.
- **sysfs** supplies driver and USB/PCI identity, while optional `nmcli` reports
  active connections and manages only the selected fallback interface.
- **stdlib `curses`** keeps installation small. Sound uses a small backend
  boundary: the zero-dependency terminal bell can be disabled and real audio
  can be added later without coupling it to the TUI. The privilege model is
  deliberately simple: run the complete program as root. It never invokes
  `sudo` itself. A small privileged helper is a possible later refinement.

This is a pragmatic machine-oriented boundary (explicit TShark fields), though
`iw` itself has no universally deployed structured-output mode. Its small,
well-established `iw dev`, `iw list`, and frequency-line formats are isolated
in `system.py`.

### Important radio details

- Disabled frequencies are excluded. `no IR`/DFS frequencies are retained:
  monitor capture is passive, and every tune is still allowed or rejected by
  nl80211/driver/regdomain. Thus channels 120/124/128 are attempted when the PHY
  advertises them. Some hardware/firmware/regdomains still refuse a DFS tune.
- Channel width is intentionally not guessed in this MVP. The table reports the
  reliable primary channel and frequency. HT/VHT/HE operation elements can be
  added later to produce `124+` only when unambiguous.
- Radiotap may contain one signal value per antenna. TShark can emit these as a
  list; 80211fox uses the strongest value, then applies an EWMA for the bar and
  beep cadence. The raw current value remains visible. RSSI is suitable for
  relative proximity tracking with the same adapter; absolute readings should
  not be compared between different adapters or driver stacks.
  HUNT's proximity wording is an estimate, not a distance measurement: walls,
  multipath, transmit power, antennas, and laptop orientation all affect RSSI.
- The selected PHY is dedicated to hunting. Its original interface is made
  unmanaged and down before a separate monitor VIF is attempted, preventing
  NetworkManager background scans from fighting channel hopping on the same
  radio. Interface-combination limits or a
  driver may reject it. Only then does 80211fox use the selected interface in
  place; it refuses that fallback when nl80211 reports an active connection or
  cannot determine association state. Its original link and NetworkManager
  states are restored during cleanup in either path.
- A monitor VIF on the same PHY does **not** create another radio: concurrent
  managed and monitor VIFs generally share a channel. Use the separate USB PHY
  described in the intended workflow for hopping without disrupting the main
  connection.

## Install

Install `python3`, `iw`, `iproute`, and `tshark` from the distribution. For
example, Fedora uses `iw`, `iproute`, and `wireshark-cli`; Debian/Ubuntu use
`iw`, `iproute2`, and `tshark`. Then:

```bash
python3 -m pip install .
sudo 80211fox
```

Or run without installing:

```bash
sudo python3 -m fox80211.cli
```

`--interface wlan1` skips adapter selection. The capture class exposes a queue
of observations and has no curses dependency, leaving room for JSON/CLI output.
The default `--sound terminal` asks the terminal to ring its bell (which terminal
settings may suppress or render visually); `--sound off` disables sound.

## Controls

In SCAN, press `2`, `5`, or `6` to toggle networks in the corresponding Wi-Fi
band (`2` = 2.4 GHz, `5` = 5 GHz, and `6` = 6 GHz); the control bar shows which
bands are enabled. Networks whose frequency
has not yet been identified remain visible. Press `D` for measured channel-tune
and sweep timing, capture/RSSI counters, and per-frequency rejection reasons;
use Up/Down to inspect every rejected frequency, then press `D` or Escape to
return. Press `H` or `?` for an in-app key reference and glossary of the table's
status labels. Press `R` to clear all accumulated
networks (live networks may be discovered again immediately). Press `F` to open
the highlighted filter field, then type to filter
dynamically by partial case-insensitive SSID or BSSID; punctuation and case in
MAC addresses are ignored. `Space` and `Q` are ordinary filter characters while
the field is active. Backspace edits, Enter commits the filter, Escape cancels
the edit, arrows select, and Enter starts HUNT outside the filter field. Space
freezes or resumes the scan, including its access-point values and ordering. In
HUNT, `B` toggles cadence beeps, `R` resets statistics, Escape returns to
scanning, and `Q` quits. Without a target frame, beeps stop and HUNT displays
`SIGNAL LOST` after two seconds on 2.4 GHz or five seconds on 5/6 GHz. SCAN sorts
all observations by smoothed RSSI, grays an AP and marks it with `?` when it was
not rediscovered during two complete channel sweeps (or after one minute
without a frame), and removes it after at least thirty minutes. Its text follows
the smoothed RSSI through a signal color gradient (with a simpler fallback on limited terminals),
while the LAST column makes observation age explicit. Its status reports
usable/rejected tunes; a failed HUNT lock is reported in SCAN rather than
terminating the program. It also reports the latest measured tune latency and
the duration of the last complete sweep, so slow driver/firmware channel
switches are visible rather than hidden in the dwell period. Scan retention is
automatically enlarged when a measured sweep requires it. HUNT stretches its signal bar to the available
terminal width.

## DFS and channel-switch diagnostics

80211fox remains entirely passive. It reads the kernel regulatory view from
`iw phy … info`, listens to local nl80211 notifications through `iw event`, and
observes CSA/ECSA elements in frames already captured by TShark. Diagnostics
report each source as available or unavailable; missing fields or driver support
reduce coverage rather than stopping capture.

- **DFS** means a channel requires Dynamic Frequency Selection.
- **RADAR** appears only after a confirmed radar-detection event from the
  selected local Linux Wi-Fi PHY.
- **DFS MOVE** means an AP announced a move away from a DFS channel. Radar is
  not confirmed: controller RRM/DCA, interference management, or manual
  configuration can also cause the move.
- **CAC** is the Channel Availability Check before using a DFS channel.
- **NOP** is the Non-Occupancy Period after radar detection, during which the
  affected channel must not be used for the regulatory-defined period.
- **CSA** is an ordinary observed Channel Switch Announcement where calling it
  DFS-related is not justified.

The selected adapter's local CAC/NOP/DFS state is **not** automatically the
state of a remote Cisco, Aruba, or other AP. A CSA alone is never presented as
confirmed radar. When a captured frame does not provide usable SSID bytes, the
UI uses the reserved marker `<MISSING>`. This often occurs for a hidden network's
zero-length beacon SSID, but it is not proof that the network is hidden: target
data frames do not contain an SSID, and capture/dissector limitations can also
make the field unavailable.

Cleanup is context-managed. Normal exit, Ctrl-C, closing the terminal (SIGHUP),
the installed SIGTERM handler, and Python exceptions stop
capture and remove the created VIF or restore the selected interface's type,
link state, and NetworkManager management. On startup, app-created `whmon<PID>`
interfaces whose owner no longer exists are removed and never appear in the
adapter picker. `SIGKILL` and machine failure cannot run in-process cleanup.

## Development

```bash
python3 -m unittest discover -v
python3 -m compileall -q fox80211 tests
```
