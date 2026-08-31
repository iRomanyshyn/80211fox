# 80211fox

A small Linux TUI for physically locating a Wi-Fi access point by SSID/BSSID,
RSSI, channel locking, and proximity beeps. It leaves unrelated Wi-Fi PHYs alone.

## Design and backend choice

The MVP uses only Python's standard library plus common distribution packages:

* **`iw`/nl80211** creates the monitor interface and tunes it. Frequencies and
  primary channel numbers come from `iw phy … info`, so the kernel's current
  regulatory view is authoritative; there is no hard-coded channel list.
* **TShark** captures passively and emits selected, tab-separated Wireshark
  fields. This avoids a home-grown radiotap/802.11 parser, Python packet
  dependencies, and Kali-specific tools. Capture is separate from the TUI.
* **sysfs** supplies driver and USB/PCI identity, while optional `nmcli` reports
  active connections and manages only the selected fallback interface.
* **stdlib `curses`** keeps installation small. The initial privilege model is
  deliberately simple: run the complete program as root. It never invokes
  `sudo` itself. A small privileged helper is a possible later refinement.

This is a pragmatic machine-oriented boundary (explicit TShark fields), though
`iw` itself has no universally deployed structured-output mode. Its small,
well-established `iw dev`, `iw list`, and frequency-line formats are isolated
in `system.py`.

### Important radio details

* Disabled frequencies are excluded. `no IR`/DFS frequencies are retained:
  monitor capture is passive, and every tune is still allowed or rejected by
  nl80211/driver/regdomain. Thus channels 120/124/128 are attempted when the PHY
  advertises them. Some hardware/firmware/regdomains still refuse a DFS tune.
* Channel width is intentionally not guessed in this MVP. The table reports the
  reliable primary channel and frequency. HT/VHT/HE operation elements can be
  added later to produce `124+` only when unambiguous.
* Radiotap may contain one signal value per antenna. TShark can emit these as a
  list; 80211fox uses the strongest value, then applies an EWMA for the bar and
  beep cadence. The raw current value remains visible.
* A separate monitor VIF is attempted first. Interface-combination limits or a
  driver may reject it. Only then does 80211fox use the selected interface in
  place; it refuses that fallback when nl80211 reports an active connection or
  cannot determine association state. NetworkManager is changed only for that
  fallback, and its original managed state is restored during cleanup.
* A monitor VIF on the same PHY does **not** create another radio: concurrent
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

## Controls

In SCAN, type to filter by partial case-insensitive SSID or BSSID; punctuation
and case in MAC addresses are ignored. Backspace edits, arrows select, and
Enter starts HUNT. In HUNT, `B` toggles cadence beeps, `R` resets statistics,
Escape returns to scanning, and `Q` quits. Proximity beeps stop when the target
has not been observed for two seconds rather than repeating a stale RSSI.

Cleanup is context-managed. Normal exit, Ctrl-C, the installed SIGTERM handler,
and Python exceptions stop
capture and remove the created VIF or restore the selected interface's type,
link state, and NetworkManager management. `SIGKILL` and machine failure cannot
be cleaned up by any process.

## Development

```bash
python3 -m unittest discover -v
python3 -m compileall -q fox80211 tests
```
