# neat-nd1000-linux

A Linux user-space driver for the **NeatDesk ND-1000** sheet-fed duplex scanner
(USB `1f44:0050`), which has no SANE support. It scans whole stacks from the
automatic feeder, both sides, in color at 300 DPI, builds one PDF per stack and can
upload it to [Paperless-ngx](https://docs.paperless-ngx.com/).

Not affiliated with or endorsed by The Neat Company.

## How it works

The ND-1000 is a Genesys **GL843** with three byte-interleaved CIS chips per side.
Rather than reimplement the chip setup, `neatscan.py` **replays USB traffic recorded
from the Windows driver** (`sequences/*.jsonl`) and waits wherever the Windows driver
waited, then decodes the raw image data itself.

| Sequence | Used for |
|---|---|
| `check.jsonl` | idle setup (the driver's per-call initialization) |
| `first.jsonl` | first sheet of a stack |
| `next.jsonl` | each further sheet |
| `release.jsonl` | eject after the last sheet |

The stack sequences were cut from a 3-sheet Windows scan at the point where the
driver reads the tray sensor, so a stack runs exactly like it does on Windows:
continue while paper is waiting, eject only at the end.

## Requirements

- Python 3 with `pyusb`, `numpy` and `Pillow`
  (Debian/Ubuntu: `sudo apt install python3-usb python3-numpy python3-pil`)
- No kernel driver claims the device, so nothing needs to be unbound.

## Install

```bash
sudo mkdir -p /opt/neatscan && sudo cp -r neatscan.py sequences /opt/neatscan/
sudo cp config.example.json /opt/neatscan/config.json    # then edit it
sudo cp systemd/60-neat-nd1000.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
```

The udev rule gives the `plugdev` group access to the scanner. Run the service as a
member of that group (edit `User=` and the paths in `systemd/neatscan.service`), and
make sure that account owns the install folder:

```bash
sudo cp systemd/neatscan.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now neatscan
journalctl -u neatscan -f
```

## Usage

```
python3 neatscan.py watch            # wait for paper; scan each stack to one PDF (+ upload)
python3 neatscan.py probe            # set up the scanner and report the paper sensor for 30 s
python3 neatscan.py scan-one OUTDIR  # scan one sheet, save raw data + decoded pages
python3 neatscan.py decode RAW OUT   # decode a saved raw sheet into two PNGs
```

`watch` keeps running if the scanner is unplugged or switched off and picks it up
again when it returns. If the scanner stops answering while still connected, it is
reset over USB (the same as a replug) and set up again; if that does not help, the log
asks for a power cycle. When the service is stopped, it finishes the current sheet,
ejects and releases the scanner before exiting, and it resets the scanner on startup. If a stack fails part-way, the pages scanned so far are saved
with `CHECK - scan error` in the name.

## Configuration (`config.json`)

| Key | Default | Meaning |
|---|---|---|
| `paperless_url` | `http://localhost:8000` | Paperless-ngx base URL |
| `token` | empty | Paperless API token; leave empty to only save PDFs locally |
| `output_dir` | `./output` | where PDFs are kept |
| `front_side` | `1` | which raw side is the front of the sheet |
| `reverse_sheets` | `true` | loaded per the tray diagram, the last sheet is fed first |
| `skip_blank` / `blank_threshold` | `true` / `0.1` | drop sides with less than 0.1 % dark pixels |
| `jpeg_quality` | `80` | JPEG quality of the pages in the PDF |
| `pause_scale` | `1.0` | experimental: replay the Windows driver's fixed pauses shorter while scanning sheets (setup and eject always run at the original timing). `0.5` worked well in testing (about 13 s per sheet instead of 15-16 s) |
| `levels` | none | per-chip correction for uneven calibration, see below |
| `refresh_minutes` | `0` | re-run the setup sequence this often while idle (`0` = never) |

### Per-chip levels

Each side is read by three sensor chips, one per third of the page. If one third looks
brighter, washed out or tinted, measure each chip's black point (darkest text, e.g. the
0.5th percentile) and white point (paper, e.g. the 90th percentile) per channel on a few
scanned pages, and enter them; each third is then mapped to black 10 / white 245.
Thirds or sides you leave out are not changed.

```json
"levels": {
  "front": {
    "left":   {"black": [0, 0, 0],       "white": [255, 255, 255]},
    "middle": {"black": [112, 101, 99],  "white": [251, 249, 251]},
    "right":  {"black": [113, 104, 104], "white": [250, 248, 251]}
  }
}
```

(These are the values from the scanner this was developed on; yours will differ.)

## Image format (for anyone extending this)

- One sheet is a fixed-length scan: 3424 lines x 15876 bytes (~11.4 in).
- Each line holds 6 planes of 2646 bytes: side A R, G, B, then side B R, G, B.
- Inside a plane the three sensor chips are byte-interleaved: byte `j` belongs to chip
  slot `j % 3` at position `j // 3`; across the page the chips are in slot order 2, 0, 1.
- Each 882-pixel chip has 4 dead pixels at the start and 15 at the end.
- Both sides arrive upside down; side B (raw planes 3-5) is also mirrored left-right,
  side A is not (the two sensors face each other).
- Status register `0x40` bit 7 is the tray sensor (set = no paper).
- Shading correction is done by the chip from tables uploaded before every sheet.

## Limitations

- **Calibration:** the shading tables, gamma curves and analog front-end gains in
  `sequences/` are the ones the Windows driver produced for the scanner that was
  recorded. Other units will scan, but may show uneven brightness. The Windows driver
  stores each scanner's own calibration in
  `C:\Users\Public\Documents\Neat ADF Scanner\<serial><dpi>_<channel>_Channel.bin`;
  the file contents (after a 6-byte header) are exactly what gets uploaded, so
  swapping them into the sequences would be the way to support other units.
- One mode only: 300 DPI, color, duplex. The recorded sequences read ~11.4 in per
  page; for longer pages the tool keeps reading while the chip still reports that it
  is scanning (experimental, logged as "long page").
- The physical Scan/PDF buttons are not supported yet (the device has an interrupt
  endpoint, `0x83`, that likely reports them).
- Tested with one scanner.

## Re-recording the sequences

`tools/windows/record.ps1` records the driver's USB traffic with USBPcap (installed with
Wireshark), and `tools/windows/trace.ps1` turns a capture into the JSON-lines format
used here (`co`/`ci` = control out/in, `bo`/`bi` = bulk out/in). Runs of identical
control reads in a trace are the driver's polling loops; the replayer waits until the
first byte matches the value the loop ended on.
