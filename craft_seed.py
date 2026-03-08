#!/usr/bin/env python3
"""
Iteratively craft a seed. Uses the release binary (fast) for testing,
detects stuck loops via MMIO trace and patches values.
"""
import subprocess, struct, re, sys

EMU = "./ghidralligator"
CONFIG = "examples/cortexm/config.json"
SEED_FILE = "fuzz_corpus/seed_crafted.bin"
SEED_SIZE = 65536  # 64KB

def run_emu_mmio(seed_path):
    """Run with -D to get MMIO trace (may be slow for many reads)."""
    cmd = [EMU, "-m", "replay", "-c", CONFIG, "-i", seed_path, "-D"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return r.stdout + r.stderr

def run_emu_fast(seed_path):
    """Run without debug (fast) to check end state."""
    cmd = [EMU, "-m", "replay", "-c", CONFIG, "-i", seed_path]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return r.stdout + r.stderr

def parse_mmio(output):
    reads = []
    for line in output.split('\n'):
        m = re.search(r'\[MMIO\] Read (0x[0-9a-f]+) size=(\d+) -> (0x[0-9a-f]+) \(cursor=(\d+)', line)
        if m:
            reads.append({
                'addr': int(m.group(1),16), 'size': int(m.group(2)),
                'val': int(m.group(3),16), 'cursor': int(m.group(4)),
                'offset': int(m.group(4)) - int(m.group(2))
            })
    return reads

def find_loop(reads, min_count=5):
    i = 0
    while i < len(reads):
        a = reads[i]['addr']
        j = i+1
        while j < len(reads) and reads[j]['addr'] == a: j += 1
        if j - i >= min_count:
            return i, a, j-i
        i = j
    return None

def main():
    seed = bytearray(b'\xff' * SEED_SIZE)
    # Known fix: offset 152 (clock switch poll)
    struct.pack_into('<I', seed, 152, 0x00000000)

    patched = {}  # offset -> set of tried values

    for it in range(1, 300):
        with open(SEED_FILE, 'wb') as f: f.write(seed)

        # First: quick check if target was hit
        try:
            fast_out = run_emu_fast(SEED_FILE)
        except subprocess.TimeoutExpired:
            fast_out = ""

        if 'ForceCrash' in fast_out or 'force_crash' in fast_out:
            print(f"Iter {it}: *** TARGET HIT! ***")
            return True

        # Get MMIO trace
        try:
            out = run_emu_mmio(SEED_FILE)
        except subprocess.TimeoutExpired:
            print(f"Iter {it}: -D timeout (too many reads). Trying to detect issue...")
            # The trace was too slow — too many MMIO reads
            # Fall back to fast run end state
            end = fast_out.strip().split('\n')[-1] if fast_out.strip() else "no output"
            print(f"  Fast end: {end}")
            break

        reads = parse_mmio(out)
        n = len(reads)
        consumed = reads[-1]['cursor'] if reads else 0

        end = ""
        if 'exhausted' in out: end = "exhausted"
        elif 'Max basic' in out: end = "maxBB"
        elif '[Crash]' in out: end = "crash"

        loop = find_loop(reads)
        if not loop:
            if end == "maxBB":
                # Error handler self-loop — not an MMIO loop
                # Need to fix the last function that returned error
                print(f"Iter {it}: reads={n} bytes={consumed} maxBB (error handler loop)")
                # Try patching reads near the end
                if n >= 3:
                    # Try the last few read offsets with different values
                    found_fix = False
                    for try_idx in range(max(0,n-5), n):
                        r = reads[try_idx]
                        off = r['offset']
                        if off not in patched:
                            patched[off] = set()
                        # Try values
                        for val in [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20]:
                            if val not in patched[off]:
                                patched[off].add(val)
                                seed[off:off+r['size']] = val.to_bytes(r['size'], 'little')
                                print(f"  Try off={off} val=0x{val:x}")
                                found_fix = True
                                break
                        if found_fix:
                            break
                    if not found_fix:
                        print("  No more fixes to try!")
                        break
                else:
                    break
            elif end == "crash":
                print(f"Iter {it}: reads={n} bytes={consumed} crash")
                for r in reads[-3:]:
                    print(f"  0x{r['addr']:x} off={r['offset']} val=0x{r['val']:x}")
                break
            elif end == "exhausted":
                print(f"Iter {it}: reads={n} bytes={consumed} exhausted")
                break
            else:
                print(f"Iter {it}: reads={n} bytes={consumed} end={end} - no loop, done")
                break
            continue

        idx, addr, cnt = loop
        # For RMW patterns: the first read is setup, second is first poll
        target_idx = idx + 1 if (idx+1 < len(reads) and reads[idx+1]['addr'] == addr) else idx
        r = reads[target_idx]
        off = r['offset']
        sz = r['size']

        if off not in patched:
            patched[off] = set()

        candidates = [
            0x00000000, 0x00000008, 0x00000010, 0x00000018,
            0x00000020, 0x00000028, 0x00000030, 0x00000038,
            0x00002000, 0x00020000, 0x02000000, 0x00000004,
            0x00000100, 0x00000002, 0x00000001, 0xFFFFFFFB,
        ]

        new_val = None
        for c in candidates:
            cv = c & ((1<<(sz*8))-1)
            if cv not in patched[off]:
                new_val = cv
                break

        if new_val is None:
            print(f"Iter {it}: exhausted candidates at off={off}")
            break

        patched[off].add(new_val)
        seed[off:off+sz] = new_val.to_bytes(sz, 'little')
        print(f"Iter {it}: reads={n} bytes={consumed} end={end} "
              f"loop@0x{addr:x} off={off} cnt={cnt} -> 0x{new_val:x}")

    print(f"\nSeed saved to {SEED_FILE}")
    for off in sorted(patched.keys()):
        current = int.from_bytes(seed[off:off+4], 'little')
        print(f"  offset {off}: 0x{current:08x}")

if __name__ == '__main__':
    main()
