#!/usr/bin/env python3
"""Linux driver for the Neat ND-1000 (USB 1f44:0050), built by replaying the
Windows driver's USB traffic recorded with USBPcap.

The scanner is a Genesys GL843. Instead of reimplementing the chip setup, this
replays recorded message sequences and waits wherever the Windows driver waited:
check.jsonl (idle setup), then for a stack first.jsonl, next.jsonl per further
sheet, and release.jsonl after the last one (cut from a 3-sheet Windows scan at
the points where the driver reads the tray sensor). Image data is decoded with the layout worked out from
the captures (see decode()).

Modes:
  watch            wait for paper; scan each stack into one PDF and upload it to Paperless
  probe            set up the scanner and print the paper sensor once a second
  scan-one OUTDIR  wait for paper, scan one sheet, save raw + decoded pages
  decode RAW OUT   decode a saved raw sheet into two page images

Settings for watch mode are read from config.json next to this file.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
VID, PID = 0x1F44, 0x0050
EP_OUT, EP_IN = 0x02, 0x81

# Raw sheet layout: each line is 6 planes of 2646 bytes (side A R,G,B then side B R,G,B).
# Inside a plane, 3 sensor chips are byte-interleaved: byte j -> chip slot j%3, position j//3.
PLANE = 2646
CHIP_POS = PLANE // 3          # 882 positions per chip
CHIP_ORDER = (2, 0, 1)         # chip slot that belongs at the left / middle / right third
DEAD_START, DEAD_END = 4, 15   # dead pixels at each end of every chip
LINE = PLANE * 6
DPI = 300
TRIM = 110                     # mean brightness above which a row/column counts as paper
LEVEL_BLACK, LEVEL_WHITE = 10, 245   # targets for per-chip levels (config "levels")

DEFAULTS = {
    'paperless_url': 'http://localhost:8000',
    'token': '',
    'output_dir': os.path.join(HERE, 'output'),
    'front_side': 1,           # which raw side holds the front of the sheet
    'reverse_sheets': True,    # loaded per the tray diagram, the last sheet is fed first
    'skip_blank': True,
    'blank_threshold': 0.1,    # % dark pixels below which a side counts as blank
    'jpeg_quality': 80,
    'poll_seconds': 1.0,
    'max_sheets': 200,
    'pause_scale': 1.0,        # experimental: <1 shortens the Windows driver's fixed pauses
    'levels': None,            # optional per-chip black/white points, see apply_levels()
}


def log(msg):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), msg, flush=True)


def load(name):
    path = os.path.join(HERE, 'sequences', name)
    if not os.path.exists(path):
        path = os.path.join(HERE, name)
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def load_config():
    cfg = dict(DEFAULTS)
    path = os.path.join(HERE, 'config.json')
    if os.path.exists(path):
        with open(path) as f:
            cfg.update(json.load(f))
    return cfg


class Scanner:
    def __init__(self):
        import usb.core
        import usb.util
        self.usb = usb
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise LookupError('Neat ND-1000 not found (is it plugged in and powered on?)')
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass
        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)

    # --- raw USB operations -------------------------------------------------
    def ctrl_out(self, op):
        data = bytes.fromhex(op['d'])
        self.dev.ctrl_transfer(op['rt'], op['rq'], op['v'], op['i'], data, timeout=5000)

    def ctrl_in(self, op):
        return bytes(self.dev.ctrl_transfer(op['rt'], op['rq'], op['v'], op['i'], op['n'], timeout=5000))

    def read_reg40(self):
        """Status register 0x40 (bit 7 set = no paper in the feeder)."""
        r = self.dev.ctrl_transfer(0xC0, 4, 0x8E, 0x4022, 2, timeout=5000)
        return r[0]

    def paper_present(self):
        return not (self.read_reg40() & 0x80)

    # --- replay --------------------------------------------------------------
    pause_scale = 1.0      # <1 replays the Windows driver's fixed pauses shorter (experimental)

    def replay(self, ops, capture=None, poll_timeout=60.0):
        """Replay recorded ops. Runs of identical control reads are the Windows
        driver's polling loops: poll until the first byte matches the value the
        loop ended on. Pauses longer than 3 ms between ops are reproduced.
        Returns the number of polling loops that timed out."""
        i, n = 0, len(ops)
        prev_t = ops[0]['t'] if ops else 0
        bulk_size = 0   # size announced by the last bulk-read header; 4-byte reads are status, not image
        timeouts = 0
        while i < n:
            op = ops[i]
            kind = op['op']
            # bulk-in ops are timestamped when the transfer finished, so the gap before
            # one is transfer time (which the read itself takes), not a pause to copy
            gap = op['t'] - prev_t
            if gap > 0.003 and kind != 'bi':
                time.sleep(min(gap, 2.0) * self.pause_scale)
            if kind == 'co':
                if op['rq'] == 4 and op['v'] == 0x82 and op['i'] == 0 and len(op['d']) == 16:
                    bulk_size = int.from_bytes(bytes.fromhex(op['d'])[4:8], 'little')
                self.ctrl_out(op)
                prev_t = op['t']
                i += 1
            elif kind == 'ci':
                key = (op['rt'], op['rq'], op['v'], op['i'], op['n'])
                j = i
                while j + 1 < n and ops[j + 1]['op'] == 'ci' and \
                        (ops[j + 1]['rt'], ops[j + 1]['rq'], ops[j + 1]['v'], ops[j + 1]['i'], ops[j + 1]['n']) == key:
                    j += 1
                if j == i:
                    self.ctrl_in(op)
                else:
                    want = bytes.fromhex(ops[j]['r'])[0]
                    start, polls = time.time(), 0
                    while True:
                        got = self.ctrl_in(op)
                        polls += 1
                        if got and got[0] == want:
                            break
                        if time.time() - start > poll_timeout:
                            log(f'  wait timed out: reg read v={op["v"]:#x} i={op["i"]:#x} '
                                f'wanted {want:#04x}, last {got.hex()} after {polls} polls; continuing')
                            timeouts += 1
                            break
                        time.sleep(0.001)
                prev_t = ops[j]['t']
                i = j + 1
            elif kind == 'bo':
                self.dev.write(EP_OUT, bytes.fromhex(op['d']), timeout=10000)
                prev_t = op['t']
                i += 1
            elif kind == 'bi':
                data = bytes(self.dev.read(EP_IN, op['n'], timeout=30000))
                if len(data) != op['n']:
                    log(f'  short bulk read: wanted {op["n"]}, got {len(data)}')
                if capture is not None and bulk_size > 4:
                    capture.append(data)
                prev_t = op['t']
                i += 1
            else:
                raise ValueError(f'unknown op {kind}')
        return timeouts


# --- image handling -----------------------------------------------------------
def apply_levels(img, chip_levels):
    """Per-chip levels: map each third's measured black/white point (per channel) to
    LEVEL_BLACK/LEVEL_WHITE. chip_levels = {"left"|"middle"|"right": {"black": [r,g,b],
    "white": [r,g,b]}}; thirds that are not listed are left alone. img must be untrimmed
    (exactly three chips wide) and in final page orientation."""
    import numpy as np
    third = img.shape[1] // 3
    v = np.arange(256, dtype=np.float32)
    for k, name in enumerate(('left', 'middle', 'right')):
        lv = chip_levels.get(name)
        if not lv:
            continue
        cols = slice(k * third, (k + 1) * third)
        for c in range(3):
            b, w = float(lv['black'][c]), float(lv['white'][c])
            lut = np.clip((v - b) / max(w - b, 1.0) * (LEVEL_WHITE - LEVEL_BLACK) + LEVEL_BLACK, 0, 255)
            img[:, cols, c] = lut.astype(np.uint8)[img[:, cols, c]]
    return img


def decode_sides(raw, levels=None, front_side=1):
    """Turn one raw sheet into two upright, trimmed RGB arrays (side 0, side 1).
    levels: optional {"front": chip_levels, "back": chip_levels}, see apply_levels()."""
    import numpy as np
    extra = len(raw) % LINE
    if extra in (4, 8):          # stray status bytes captured ahead of the image
        raw = raw[extra:]
    a = np.frombuffer(raw, dtype=np.uint8)
    lines = len(a) // LINE
    a = a[:lines * LINE].reshape(lines, 6, CHIP_POS, 3)       # line, plane, position, chip slot
    keep = slice(DEAD_START, CHIP_POS - DEAD_END)
    sides = []
    for side in (0, 1):
        chans = []
        for c in range(3):
            plane = a[:, side * 3 + c]                         # lines x positions x chip slots
            chans.append(np.concatenate([plane[:, keep, slot] for slot in CHIP_ORDER], axis=1))
        img = np.stack(chans, axis=2)[::-1]                     # upright: both sensors deliver upside down
        if side == 1:
            img = img[:, ::-1]                                   # side 1's sensor also mirrors left-right
        chip_levels = (levels or {}).get('front' if side == front_side else 'back')
        if chip_levels:
            img = apply_levels(np.ascontiguousarray(img), chip_levels)
        # trim to the paper: rows/columns brighter than TRIM count as paper. The strip a
        # sensor sees before the paper arrives reads ~70, paper ~220+, dense text rows ~180.
        bright = img.mean(axis=2)
        rows = np.where(bright.mean(axis=1) > TRIM)[0]
        cols = np.where(bright[rows[0]:rows[-1] + 1].mean(axis=0) > TRIM)[0] if len(rows) else []
        if len(rows) and len(cols):
            img = img[rows[0]:rows[-1] + 1, cols[0]:cols[-1] + 1]
        sides.append(np.ascontiguousarray(img))
    return sides


def ink_percent(img):
    """% of dark pixels on a ~200 px wide copy, ignoring a 6% border (edge shading).
    Calibrated on this scanner under Linux: blank side 0%, light handwritten page ~3%."""
    import numpy as np
    step = max(1, img.shape[1] // 200)
    h2, w2 = img.shape[0] // step, img.shape[1] // step
    small = img[:h2 * step, :w2 * step].reshape(h2, step, w2, step, 3).mean(axis=(1, 3))   # block average
    light = (small.max(axis=2) + small.min(axis=2)) / 2 / 255.0   # HSL lightness
    my, mx = int(light.shape[0] * 0.06), int(light.shape[1] * 0.06)
    core = light[my:light.shape[0] - my, mx:light.shape[1] - mx]
    return 100.0 * (core < 0.55).mean() if core.size else 0.0


def save_jpeg(img, path, quality):
    from PIL import Image
    Image.fromarray(img).save(path, 'JPEG', quality=quality, dpi=(DPI, DPI))


def decode(raw, out_prefix):
    """decode mode: write both sides as PNG."""
    from PIL import Image
    paths = []
    cfg = load_config()
    for side, img in enumerate(decode_sides(raw, cfg['levels'], cfg['front_side'])):
        path = f'{out_prefix}_side{side}.png'
        Image.fromarray(img).save(path, dpi=(DPI, DPI))
        log(f'  side {side}: {img.shape[1]}x{img.shape[0]} -> {path}  (ink {ink_percent(img):.2f}%)')
        paths.append(path)
    return paths


def write_pdf(jpegs, pdf_path):
    """Minimal PDF: one JPEG per page, embedded as-is (no recompression)."""
    from PIL import Image
    objs = []                                   # (number, bytes)
    kids = []
    for k, jp in enumerate(jpegs):
        with Image.open(jp) as im:
            w, h = im.size
            gray = im.mode == 'L'
        with open(jp, 'rb') as f:
            data = f.read()
        p = 3 + 3 * k
        pw, ph = round(w * 72 / DPI, 2), round(h * 72 / DPI, 2)
        kids.append(f'{p} 0 R')
        objs.append((p, f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {pw} {ph}] '
                        f'/Resources << /XObject << /Im0 {p + 1} 0 R >> >> /Contents {p + 2} 0 R >>'.encode()))
        objs.append((p + 1, (f'<< /Type /XObject /Subtype /Image /Width {w} /Height {h} '
                             f'/ColorSpace /{"DeviceGray" if gray else "DeviceRGB"} /BitsPerComponent 8 '
                             f'/Filter /DCTDecode /Length {len(data)} >>\nstream\n').encode() + data + b'\nendstream'))
        content = f'q {pw} 0 0 {ph} 0 0 cm /Im0 Do Q'.encode()
        objs.append((p + 2, b'<< /Length %d >>\nstream\n' % len(content) + content + b'\nendstream'))
    objs.insert(0, (2, f'<< /Type /Pages /Kids [{" ".join(kids)}] /Count {len(jpegs)} >>'.encode()))
    objs.insert(0, (1, b'<< /Type /Catalog /Pages 2 0 R >>'))
    out = io.BytesIO()
    out.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = {}
    for num, body in objs:
        offsets[num] = out.tell()
        out.write(b'%d 0 obj\n' % num + body + b'\nendobj\n')
    xref = out.tell()
    count = max(offsets) + 1
    out.write(b'xref\n0 %d\n0000000000 65535 f \n' % count)
    for num in range(1, count):
        out.write(b'%010d 00000 n \n' % offsets[num])
    out.write(b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (count, xref))
    with open(pdf_path, 'wb') as f:
        f.write(out.getvalue())


def upload(pdf_path, cfg):
    """POST the PDF to Paperless-ngx's document API."""
    boundary = uuid.uuid4().hex
    name = os.path.basename(pdf_path)
    with open(pdf_path, 'rb') as f:
        pdf = f.read()
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\n'
            f'{os.path.splitext(name)[0]}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{name}"\r\n'
            f'Content-Type: application/pdf\r\n\r\n').encode() + pdf + f'\r\n--{boundary}--\r\n'.encode()
    req = urllib.request.Request(cfg['paperless_url'].rstrip('/') + '/api/documents/post_document/', data=body,
                                 headers={'Authorization': f'Token {cfg["token"]}',
                                          'Content-Type': f'multipart/form-data; boundary={boundary}'})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read().decode(errors='replace').strip()


def scan_stack(s, seq, cfg):
    """Scan sheets while paper remains, the way the Windows driver does a stack:
    'first' for sheet 1, then after each sheet read the tray sensor (as Windows does
    at that exact point) and either replay 'next' for another sheet or 'release' to
    eject and stop. Returns (pages, workdir, had_error); pages are JPEG paths in page order."""
    from concurrent.futures import ThreadPoolExecutor
    work = tempfile.mkdtemp(prefix='neatscan-')
    jobs = []              # per sheet: future -> [front_jpeg, back_jpeg] (None for blank sides)
    had_error = False
    segment = seq['first']
    order = (cfg['front_side'], 1 - cfg['front_side'])

    def process(raw, idx):
        """Decode, drop blank sides and save JPEGs - runs while the next sheet scans."""
        sides = decode_sides(raw, cfg['levels'], cfg['front_side'])
        pair = []
        for k, side in enumerate(order):
            img = sides[side]
            if cfg['skip_blank'] and ink_percent(img) < cfg['blank_threshold']:
                pair.append(None)
                continue
            path = os.path.join(work, f's{idx:03d}_{k}.jpg')
            save_jpeg(img, path, cfg['jpeg_quality'])
            pair.append(path)
        log(f'  sheet {idx + 1}: {sum(p is not None for p in pair)} side(s) kept')
        return pair

    pool = ThreadPoolExecutor(max_workers=1)
    while len(jobs) < cfg['max_sheets']:
        t0 = time.time()
        chunks = []
        try:
            timeouts = s.replay(segment, capture=chunks)
        except s.usb.core.USBError as e:
            log(f'  USB error during sheet {len(jobs) + 1} (jam or misfeed?): {e}')
            had_error = True
            break
        raw = b''.join(chunks)
        if len(raw) < LINE * 1000:
            log(f'  sheet {len(jobs) + 1}: only {len(raw):,} bytes of image data; stopping this stack')
            had_error = True
            break
        log(f'  sheet {len(jobs) + 1} scanned in {time.time() - t0:.1f} s'
            + (f', {timeouts} wait timeout(s)' if timeouts else ''))
        jobs.append(pool.submit(process, raw, len(jobs)))
        if timeouts:
            had_error = True
        if not s.paper_present():
            break
        segment = seq['next']
    try:
        s.replay(seq['release'])  # eject the last sheet
        s.replay(seq['check'])    # and leave the scanner idle the way Windows does
    except s.usb.core.USBError as e:
        log(f'  USB error while releasing the last sheet: {e}')
    sheets = []
    for k, j in enumerate(jobs):          # wait for the last sheet(s) to finish processing
        try:
            sheets.append(j.result())
        except Exception as e:
            log(f'  sheet {k + 1}: processing failed ({e}); page(s) left out')
            sheets.append([None, None])
            had_error = True
    pool.shutdown()
    if cfg['reverse_sheets']:
        sheets.reverse()
    pages = [p for pair in sheets for p in pair if p is not None]
    return pages, work, had_error


def watch():
    """Runs forever: survives the scanner being unplugged or switched off by waiting
    for it to reappear, so the service never has to restart."""
    import usb.core
    import usb.util
    cfg = load_config()
    os.makedirs(cfg['output_dir'], exist_ok=True)
    seq = {name: load(f'{name}.jsonl') for name in ('check', 'first', 'next', 'release')}
    can_upload = bool(cfg['token']) and not cfg['token'].startswith('PASTE')
    waiting = False
    while True:
        try:
            s = Scanner()
        except (LookupError, usb.core.USBError) as e:
            if not waiting:
                log(f'scanner not available ({e}); waiting for it to be connected')
                waiting = True
            time.sleep(5)
            continue
        waiting = False
        try:
            s.pause_scale = float(cfg['pause_scale'])
            s.replay(seq['check'])
            log(f'watching feeder (upload: {cfg["paperless_url"] if can_upload else "off - no token in config.json"}'
                + (f', pause_scale {s.pause_scale}' if s.pause_scale != 1.0 else '') + ')')
            watch_feeder(s, seq, cfg, can_upload)
        except usb.core.USBError as e:
            log(f'scanner disconnected or stopped responding ({e}); waiting for it to come back')
            try:
                usb.util.dispose_resources(s.dev)   # free the stale handle before reconnecting
            except Exception:
                pass
            waiting = True
            time.sleep(5)


def watch_feeder(s, seq, cfg, can_upload):
    """Wait for paper and scan stacks until the scanner goes away (USBError)."""
    while True:
        if not s.paper_present():
            time.sleep(cfg['poll_seconds'])
            continue
        stamp = time.strftime('%Y-%m-%d_%H%M%S')
        log('paper detected, scanning stack...')
        pages, work, had_error = scan_stack(s, seq, cfg)
        try:
            if not pages:
                log('  nothing to save (all sides blank)')
                continue
            name = f'Scan {stamp}' + (' CHECK - scan error' if had_error else '')
            pdf = os.path.join(cfg['output_dir'], name + '.pdf')
            write_pdf(pages, pdf)
            log(f'saved {len(pages)} page(s) -> {pdf} ({os.path.getsize(pdf) / 1e6:.1f} MB)')
            if can_upload:
                try:
                    log(f'uploaded to Paperless (response: {upload(pdf, cfg)})')
                except Exception as e:     # keep scanning even if Paperless is down
                    log(f'UPLOAD FAILED ({e}); the PDF is still in {cfg["output_dir"]}')
        finally:
            shutil.rmtree(work, ignore_errors=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('watch', 'probe', 'scan-one', 'decode'):
        sys.exit(__doc__)
    mode = sys.argv[1]

    if mode == 'watch':
        watch()
        return

    if mode == 'decode':
        with open(sys.argv[2], 'rb') as f:
            decode(f.read(), sys.argv[3])
        return

    try:
        s = Scanner()
    except LookupError as e:
        sys.exit(str(e))
    check = load('check.jsonl')
    log('setting up scanner (replaying the Windows check sequence)')
    s.replay(check)
    log(f'setup done; status register 0x40 = {s.read_reg40():#04x}')

    if mode == 'probe':
        log('reporting the paper sensor for 30 s - put a sheet in and take it out')
        last = None
        for _ in range(30):
            p = s.paper_present()
            if p != last:
                log(f'  paper in feeder: {"YES" if p else "no"}  (reg 0x40 = {s.read_reg40():#04x})')
                last = p
            time.sleep(1)
        log('probe finished')
        return

    outdir = sys.argv[2] if len(sys.argv) > 2 else '.'
    os.makedirs(outdir, exist_ok=True)
    log('waiting for paper...')
    while not s.paper_present():
        time.sleep(1)
    log('paper detected - scanning one sheet')
    chunks = []
    t0 = time.time()
    s.replay(load('first.jsonl'), capture=chunks)
    raw = b''.join(chunks)
    log(f'sheet done in {time.time() - t0:.1f} s: {len(raw):,} bytes (expected 54,232,416)')
    s.replay(load('release.jsonl'))
    stamp = time.strftime('%Y%m%d-%H%M%S')
    raw_path = os.path.join(outdir, f'sheet-{stamp}.raw')
    with open(raw_path, 'wb') as f:
        f.write(raw)
    log(f'raw data saved to {raw_path}')
    s.replay(check)
    decode(raw, os.path.join(outdir, f'sheet-{stamp}'))


if __name__ == '__main__':
    main()
