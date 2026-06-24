#!/usr/bin/env python3
"""
translator.py — Convert tripletest_output.bin to JSON and/or H5.

Usage:
  python translator.py tripletest_output.bin              # pretty-print + summary
  python translator.py tripletest_output.bin out.json     # also write JSON
  python translator.py tripletest_output.bin out.h5       # write H5 (needs h5py)

The JSON output uses hex strings for binary buffers so it is human-readable.
The H5 output stores byte arrays directly for compact storage.
"""

import struct, sys, os, json
from pathlib import Path

MAGIC   = b'TWTB'
VERSION = 1

REC_MODULE_LOAD   = 0x01
REC_CALLBACK_IN   = 0x02
REC_CALLBACK_OUT  = 0x03
REC_THREAD_EVENT  = 0x04
REC_PROCESS_EXIT  = 0x05

REC_NAMES = {
    REC_MODULE_LOAD:  'MODULE_LOAD',
    REC_CALLBACK_IN:  'CALLBACK_IN',
    REC_CALLBACK_OUT: 'CALLBACK_OUT',
    REC_THREAD_EVENT: 'THREAD_EVENT',
    REC_PROCESS_EXIT: 'PROCESS_EXIT',
}


def read_u8 (buf, off): return struct.unpack_from('<B', buf, off)[0], off+1
def read_u32(buf, off): return struct.unpack_from('<I', buf, off)[0], off+4
def read_u64(buf, off): return struct.unpack_from('<Q', buf, off)[0], off+8


def parse_file(path: str):
    data = Path(path).read_bytes()
    off  = 0

    magic = data[off:off+4]; off += 4
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")

    version = struct.unpack_from('<I', data, off)[0]; off += 4
    qpc_freq = struct.unpack_from('<Q', data, off)[0]; off += 8

    print(f"TWTB v{version}  qpc_freq={qpc_freq}")

    records = []

    while off + 13 <= len(data):
        rec_type = data[off]; off += 1
        size     = struct.unpack_from('<I', data, off)[0]; off += 4
        qpc      = struct.unpack_from('<Q', data, off)[0]; off += 8
        payload  = data[off:off+size]; off += size

        ts = qpc / qpc_freq          # seconds since QPC epoch

        rec = {
            'type':    REC_NAMES.get(rec_type, f'UNKNOWN_{rec_type:#04x}'),
            'type_id': rec_type,
            'time_s':  ts,
        }

        if rec_type == REC_MODULE_LOAD:
            base,     p = read_u64(payload, 0)
            img_size, p = read_u64(payload, p)
            nlen,     p = read_u32(payload, p)
            name = payload[p:p+nlen].decode('utf-8', errors='replace')
            rec.update(base=hex(base), img_size=img_size, name=name,
                       name_leaf=os.path.basename(name))
            print(f"  MODULE_LOAD  {os.path.basename(name):30s} base={hex(base)}")

        elif rec_type == REC_CALLBACK_IN:
            p = 0
            seq,       p = read_u64(payload, p)
            api,       p = read_u32(payload, p)
            inlen,     p = read_u32(payload, p)
            input_buf  = payload[p:p+inlen]; p += inlen
            rip,   p = read_u64(payload, p)
            rsp,   p = read_u64(payload, p)
            input_ptr, p = read_u64(payload, p)
            flen,  p = read_u32(payload, p)
            frame_dump = payload[p:p+flen]
            rec.update(
                seq=seq, api=api,
                input=input_buf.hex(),
                input_bytes=list(input_buf),
                input_ptr=hex(input_ptr),
                rip=hex(rip), rsp=hex(rsp),
                frame=frame_dump.hex(),
            )
            print(f"  CALLBACK_IN  seq={seq:<4}  api={api:<4}  inlen={inlen}  inptr={hex(input_ptr)}")

        elif rec_type == REC_CALLBACK_OUT:
            p = 0
            seq,    p = read_u64(payload, p)
            status, p = read_u32(payload, p)
            outlen, p = read_u32(payload, p)
            out_buf   = payload[p:p+outlen]
            rec.update(
                seq=seq, status=hex(status),
                output=out_buf.hex(),
                output_bytes=list(out_buf),
            )
            print(f"  CALLBACK_OUT seq={seq:<4}  status={hex(status)}  outlen={outlen}")

        elif rec_type == REC_THREAD_EVENT:
            p = 0
            tid,   p = read_u32(payload, p)
            start, p = read_u64(payload, p)
            rec.update(tid=tid, start_addr=hex(start))
            print(f"  THREAD_EVENT tid={tid}  start={hex(start)}")

        elif rec_type == REC_PROCESS_EXIT:
            code = struct.unpack_from('<I', payload, 0)[0]
            rec.update(exit_code=code)
            print(f"  PROCESS_EXIT code={code}")

        else:
            rec['raw'] = payload.hex()

        records.append(rec)

    return records, qpc_freq


def summarise(records):
    cb_in  = [r for r in records if r['type_id'] == REC_CALLBACK_IN]
    cb_out = [r for r in records if r['type_id'] == REC_CALLBACK_OUT]
    mods   = [r for r in records if r['type_id'] == REC_MODULE_LOAD]

    print(f"\n{'='*60}")
    print(f"Summary")
    print(f"{'='*60}")
    print(f"  Total records   : {len(records)}")
    print(f"  Module loads    : {len(mods)}")
    print(f"  Callback IN     : {len(cb_in)}")
    print(f"  Callback OUT    : {len(cb_out)}")
    print()
    print("Callback IN sequence (ApiNumber | input length):")
    for r in cb_in:
        print(f"  seq={r['seq']:<4}  api={r['api']:<4}  inlen={len(r['input'])//2}")
    print()
    print("Modules loaded:")
    for m in mods:
        print(f"  {m['name_leaf']:40s} @ {m['base']}")


def write_h5(records, qpc_freq, out_path):
    import h5py
    import numpy as np

    cb_in  = [r for r in records if r['type_id'] == REC_CALLBACK_IN]
    cb_out = [r for r in records if r['type_id'] == REC_CALLBACK_OUT]
    mods   = [r for r in records if r['type_id'] == REC_MODULE_LOAD]

    with h5py.File(out_path, 'w') as hf:
        g = hf.create_group('tripletest')
        g.attrs['qpc_freq'] = qpc_freq

        # Callbacks IN
        ci = g.create_group('callbacks_in')
        if cb_in:
            ci.create_dataset('seq',    data=np.array([r['seq'] for r in cb_in],   dtype=np.uint64))
            ci.create_dataset('api',    data=np.array([r['api'] for r in cb_in],   dtype=np.uint32))
            ci.create_dataset('time_s', data=np.array([r['time_s'] for r in cb_in], dtype=np.float64))
            # input data (variable-length, padded)
            max_in = max((len(r['input_bytes']) for r in cb_in), default=1)
            in_arr = np.zeros((len(cb_in), max_in), dtype=np.uint8)
            in_len = np.zeros(len(cb_in), dtype=np.uint32)
            for i, r in enumerate(cb_in):
                b = r['input_bytes']
                in_arr[i, :len(b)] = b
                in_len[i] = len(b)
            ci.create_dataset('input_data',   data=in_arr)
            ci.create_dataset('input_length', data=in_len)
            ci.create_dataset('input_ptr', data=np.array([int(r['input_ptr'], 16) for r in cb_in], dtype=np.uint64))
            ci.create_dataset('rip', data=np.array([int(r['rip'], 16) for r in cb_in], dtype=np.uint64))
            ci.create_dataset('rsp', data=np.array([int(r['rsp'], 16) for r in cb_in], dtype=np.uint64))
            # KCALLOUT_FRAME raw dump (256 bytes each)
            max_f = max((len(bytes.fromhex(r.get('frame',''))) for r in cb_in), default=1)
            f_arr = np.zeros((len(cb_in), max_f), dtype=np.uint8)
            for i, r in enumerate(cb_in):
                fb = bytes.fromhex(r.get('frame', ''))
                f_arr[i, :len(fb)] = list(fb)
            ci.create_dataset('frame_dump', data=f_arr)

        # Callbacks OUT
        co = g.create_group('callbacks_out')
        if cb_out:
            co.create_dataset('seq',    data=np.array([r['seq'] for r in cb_out], dtype=np.uint64))
            co.create_dataset('status', data=np.array([int(r['status'], 16) for r in cb_out], dtype=np.uint32))
            co.create_dataset('time_s', data=np.array([r['time_s'] for r in cb_out], dtype=np.float64))
            max_out = max((len(r['output_bytes']) for r in cb_out), default=0)
            out_arr = np.zeros((len(cb_out), max(max_out, 1)), dtype=np.uint8)
            out_len = np.zeros(len(cb_out), dtype=np.uint32)
            for i, r in enumerate(cb_out):
                b = r['output_bytes']
                out_arr[i, :len(b)] = b
                out_len[i] = len(b)
            co.create_dataset('output_data',   data=out_arr)
            co.create_dataset('output_length', data=out_len)

        # Modules
        gm = g.create_group('modules')
        if mods:
            dt_str = h5py.string_dtype()
            names  = [m['name'] for m in mods]
            bases  = [int(m['base'], 16) for m in mods]
            gm.create_dataset('name',     data=np.array(names,  dtype=object), dtype=dt_str)
            gm.create_dataset('base',     data=np.array(bases,  dtype=np.uint64))
            gm.create_dataset('img_size', data=np.array([m['img_size'] for m in mods], dtype=np.uint64))

    print(f"\nH5 written to: {out_path}")


def write_json(records, out_path):
    # Remove large 'stack' and 'input_bytes'/'output_bytes' arrays from JSON to keep it readable;
    # keep them in 'input' and 'output' as hex strings
    def slim(r):
        s = {k: v for k, v in r.items()
             if k not in ('frame', 'input_bytes', 'output_bytes')}
        return s
    with open(out_path, 'w') as f:
        json.dump({'records': [slim(r) for r in records]}, f, indent=2)
    print(f"JSON written to: {out_path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    in_path  = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) >= 3 else None

    records, qpc_freq = parse_file(in_path)
    summarise(records)

    if out_path:
        if out_path.endswith('.h5') or out_path.endswith('.hdf5'):
            write_h5(records, qpc_freq, out_path)
        else:
            write_json(records, out_path)
