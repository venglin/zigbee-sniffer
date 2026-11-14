# zigbee-sniffer

A software receiver for IEEE 802.15.4 / Zigbee (2.4 GHz O-QPSK PHY) for the **HackRF One**,
written in Python with only `numpy` and `scipy`.

It demodulates frames in real time, checks the FCS, prints a decoded MAC / Zigbee NWK
summary of every frame and writes a PCAP that Wireshark dissects down to Zigbee APS/ZCL.

```
01:00:00.002 ch15  -10.4dBFS snr 14.1 cfo  -35.0k lqi 255 len  28  Beacon seq=85 pan=0x1234 0x0000 -> - PAN-coord assoc=yes ZigbeePRO v2 depth=0 router_cap=1 ed_cap=1 epid=dd:dd:dd:dd:dd:dd:dd:dd
01:00:00.003 ch15  -10.4dBFS snr 14.2 cfo  -35.0k lqi 255 len  49  Data seq=33 pan=0x1234 0x0000 -> 0x0001 [A] NWK Data 0x0000->0x0001 r=30 nseq=7 enc(network key fc=1000 src=02:00:00:00:00:00:00:01 kseq=0)
01:00:00.006 ch15  -10.4dBFS snr 14.1 cfo  -35.0k lqi 255 len   5  Ack seq=33
```

Highlights:

- **Sensitive.** Detection uses a chip-differential correlator and decoding is coherent.
  Together they decode 50 % of frames at **−4 dB SNR** (2 MHz bandwidth), about 8 dB better
  than a classic FM-discriminator receiver (included for comparison).
- **Robust.** It is tested with ±150 kHz carrier offset and ±100 ppm clock drift, and keeps
  the HackRF DC spike out of band by tuning the LO 2 MHz off the channel.
- **Fast enough.** About 2.5× real time on a desktop CPU (≈35 % of one core live).
- **Wireshark ready.** It writes `LINKTYPE_IEEE802_15_4_TAP` PCAPs with the channel number.
- **No GNU Radio.** libhackrf is driven directly through `ctypes`.

## Installation

```sh
git clone https://github.com/venglin/zigbee-sniffer
cd zigbee-sniffer
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[test]"
```

Requirements: Python ≥ 3.10, `numpy`, `scipy` and **libhackrf**:

- **Windows:** install [PothosSDR](https://downloads.myriadrf.org/builds/PothosSDR/).
  `hackrf.dll` is looked up in PothosSDR, radioconda, SDRangel and Universal Radio Hacker.
  Set `HACKRF_DLL` to the full path of the DLL to use another one.
- **Linux / macOS:** install libhackrf from your package manager (`libhackrf0`,
  `hackrf` in Homebrew). The library is found via `ctypes.util.find_library`.

Development and real-world testing were done on Windows 11 with PothosSDR. The DSP and
tests also run on Linux (see CI), but the HackRF path on Linux/macOS has not been tested
with hardware.

## Usage

```sh
# try it without hardware: decode the bundled synthetic recording
zbdemod file examples/synthetic.cs8 --pcap out.pcap

# find networks: hop over channels 11-26, 5 s each
zbdemod scan

# decode one channel live and save a PCAP (Ctrl+C stops)
zbdemod live -c 15 --pcap ch15.pcap

# record raw IQ (int8, 16 MB/s) with a .json sidecar, decode it later
zbdemod record -c 15 -d 20 -o ch15.cs8
zbdemod file ch15.cs8 --pcap ch15.pcap

# synthetic end-to-end benchmark: decoded frames vs SNR for all receiver variants
zbdemod selftest
```

`python -m zbdemod ...` works too, without installing the package.

Common options:

| option | meaning |
|---|---|
| `--pcap FILE` | write frames with a valid FCS to a PCAP file |
| `--hex` | print frame bytes |
| `--bad` | also report (and write) frames with a bad FCS |
| `--lna N`, `--vga N` | HackRF gains (default 40 / 30 dB, see below) |
| `--amp` | enable the HackRF +14 dB RF amplifier |
| `--status N` | status line every N s: noise level, clipped samples, dropped USB blocks, CPU load |
| `--method coherent\|disc` | symbol decoder (default `coherent`) |
| `--detector diff\|disc` | frame detector (default `diff`; `disc` is the only one for `--method disc`) |
| `--threshold X` | detection threshold 0..1 (default 0.22 `diff`, 0.30 `disc`+coherent, 0.45 `disc`+`disc`) |

Output columns: local time, channel, signal power in dBFS, SNR relative to the running
noise floor, carrier offset of the transmitter relative to the HackRF, an approximate LQI
derived from chip errors, PSDU length, then the decoded frame. MAC flags: `S` security,
`P` frame pending, `A` ACK requested.

### Live capture in Wireshark

Install the extcap interface once:

```sh
zbdemod extcap-install            # remove with: zbdemod extcap-install --uninstall
```

Wireshark then lists **Zigbee / IEEE 802.15.4 (HackRF One)** as a capture interface.
Its options (the gear icon) set the channel, gains, decoder and detection threshold,
or select a recording instead of the HackRF. Frames appear live. The interface also
works from tshark, e.g. `tshark -i zbdemod -o extcap.zbdemod.channel:15`.

Without extcap, stream PCAP through a pipe instead. Frame lines then go to stderr:

```sh
zbdemod live -c 15 --pcap - | wireshark -k -i -
```

### Wireshark

PCAPs use `LINKTYPE_IEEE802_15_4_TAP` (283) with FCS-type and channel TLVs. Wireshark
decodes 802.15.4 → Zigbee NWK → APS → ZCL. Zigbee NWK traffic is encrypted with the
network key. Add the key under *Preferences → Protocols → ZigBee → Security Keys* to
decrypt it. If you capture a device joining, the network key is sent encrypted with the
well-known default trust-center link key `ZigBeeAlliance09`, which Wireshark knows.

### Gain settings

The defaults (LNA 40 dB, VGA 30 dB) matter. With HackRF's usual 32/20 dB, the noise
floor after the channel filter sat at the int8 ADC quantisation floor (≈ −52 dBFS),
and about 3× fewer frames were received. Use the `--status` line: aim for a noise floor
around −42 dBFS and lower `--vga` if the clipped-sample percentage goes above ~0.1 %.

The HackRF RF amplifier (`--amp`) is a common failure point (it is easily damaged by
strong signals or ESD). If enabling it makes signals disappear instead of getting 14 dB
stronger, the amplifier is broken. Leave it off.

## How it works

```
HackRF 8 Msps, LO = channel + 2 MHz        (HackRF DC spike falls outside the channel)
  → mix by +2 MHz                          (periodic table: fs/4 → j^n)
  → 1.3 MHz low-pass FIR, decimate ×2 → 4 Msps (2 samples per chip)
  → frame detection (default "diff"):
       · half-sine chip matched filter z[n]
       · chip-differential product x[n] = z[n] · z*[n + 1 chip]
       · normalised correlation of x with the ideal SHR (6 preamble symbols + SFD),
         one overlap-add convolution; the phase of the peak is a coarse CFO estimate
  → coherent decoder (default), on the 8 Msps complex signal:
       · half-sine matched filter for every chip
       · SFD alignment check over ±2 symbols (periodic preamble side lobes)
       · from the known SHR chips: fine CFO (FFT over 4-chip blocks, ±200 kHz),
         carrier phase and fractional timing
       · 32-chip correlation with the 16 symbol patterns, coherent decisions with
         decision-directed phase tracking
       · clock drift: per-symbol non-coherent timing peak + weighted line fit anchored
         on the SHR
  → PHR (length) → PSDU → CRC-16 (ITU-T, a.k.a. CRC-16/KERMIT)
```

Background: O-QPSK with half-sine pulses is mathematically MSK. During chip interval
*n* the instantaneous frequency has the sign `(-1)^(n+1)·a[n]·a[n-1]` (`a = ±1`), which
depends only on two neighbouring chips.

- The **`disc` variants** use this through an FM discriminator `arg(y[n]·y*[n-1])`. It
  needs no carrier phase, and a carrier offset becomes a DC term. The `disc` decoder
  correlates 31 chips, because the first chip of a symbol depends on the previous
  symbol. At low SNR, however, `arg()` amplifies noise (the FM threshold effect).
- The **chip-differential product** `z[n]·z*[n+1]` carries the same neighbouring-chip
  information without `arg()`. It keeps the amplitude, so it has no threshold effect.
  It is also complex: a carrier offset only rotates it by a constant angle (27° at
  150 kHz) instead of adding a DC term. It can therefore be summed coherently over the
  whole SHR, and the magnitude of the correlation does not depend on the offset. This
  detector is ~3.2 dB more sensitive than the discriminator-based one, and cheaper.
- The **coherent decoder** gains another ~4.4 dB over the discriminator decoder.

Pitfalls worth knowing about, all handled:

- The preamble is periodic, so the SHR correlation has strong side lobes at whole-symbol
  shifts (≈ 6/8 of the peak with 6 preamble symbols in the template), and weaker ones up
  to 8 symbols early. After the first threshold crossing, the true peak is searched over
  a full SHR length (10 symbols).
- At low SNR, noise can lift a side lobe above the true peak. The coherent decoder
  therefore checks ±2 symbol shifts and keeps the one where the SFD matches coherently.
- A detection that ends with a bad FCS must not "consume" the span of its supposed
  frame. False detections decode a garbage length field, and skipping that span could
  hide a real frame.

## Results

Synthetic benchmark (`zbdemod selftest`, 100 random frames of 5–127 bytes per point,
CFO 80 kHz, clock offset 60 ppm). Values are the share of frames decoded with a valid FCS:

| SNR (2 MHz) | −5 dB | −4 dB | −3 dB | −2 dB | −1 dB | 0 dB | 1 dB | 2 dB | 3 dB | 4 dB | 5 dB | 7 dB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `diff` + coherent (default) | 13 % | 53 % | 82 % | 99 % | 100 % | 100 % | 100 % | 100 % | 100 % | 100 % | 100 % | 100 % |
| `disc` + coherent | 0 % | 2 % | 1 % | 16 % | 42 % | 81 % | 97 % | 100 % | 100 % | 100 % | 100 % | 100 % |
| `disc` + `disc` | 0 % | 0 % | 0 % | 0 % | 0 % | 0 % | 0 % | 2 % | 13 % | 59 % | 92 % | 100 % |

The 50 % points are −4.1 dB, −0.8 dB and 3.8 dB.

Real world: a 20 s recording of a home Zigbee network (one coordinator and about a
dozen routers, including lights), decoded with each variant. "Transmitters seen" also
counts one device of a neighbouring network:

| detector + decoder, threshold | frames with valid FCS | bad FCS | detections | transmitters seen | speed |
|---|---|---|---|---|---|
| `disc` + `disc`, 0.45 | 80 | 4 | 85 | 8 | 2.0× |
| `disc` + coherent, 0.30 | 100 | 13 | 114 | 13 | 1.8× |
| `diff` + coherent, 0.22 (default) | 115 | 37 | 157 | 15 | 2.5× |
| `diff` + coherent, 0.20 | 115 | 279 | 419 | 15 | 2.2× |

- Every frame found by a weaker variant is also found by the stronger ones.
- The weakest frames decoded by the default receiver were only ~1.5 dB above the noise
  floor.
- Lowering the threshold below the default only added false detections on real
  interference. The FCS rejects them, but with hundreds of garbage frames per minute
  one would eventually pass the 16-bit CRC by chance.

## Project layout

| path | contents |
|---|---|
| `zbdemod/phy.py` | PHY constants, chip table, MSK patterns, reference modulator |
| `zbdemod/demod.py` | streaming demodulator: `diff`/`disc` detectors, coherent/`disc` decoders |
| `zbdemod/mac.py` | FCS, IEEE 802.15.4 MAC and Zigbee NWK/APS header parser |
| `zbdemod/pcap.py` | PCAP writer (802.15.4 TAP) |
| `zbdemod/hackrf.py` | `ctypes` binding to libhackrf (streaming RX, retuning) |
| `zbdemod/sim.py` | channel simulator (CFO, phase, clock drift, AWGN, IF offset) |
| `zbdemod/cli.py` | `live`, `scan`, `record`, `file`, `selftest` commands |
| `examples/` | synthetic IQ recording, its decoded PCAP and the generator script |
| `tests/` | pytest suite |

## Tests

```sh
pytest
```

The tests need no hardware. They cover:

- the chip table against the standard and the MSK sign rule against the modulator;
- the CRC against the example from the standard;
- all three receiver variants at ±150 kHz CFO and ±100 ppm clock drift, and the
  accuracy of the CFO estimate;
- the sensitivity advantage of the coherent decoder and of the `diff` detector;
- SFD alignment when a detection is forced 1–2 symbols off;
- an ACK 192 µs after a data frame;
- no false frames on pure noise;
- the PCAP layout.

## Limitations and ideas

- 2.4 GHz O-QPSK PHY only (channels 11–26). No sub-GHz PHYs, no 802.15.4g/e features
  beyond header parsing.
- No decryption. Use Wireshark with the network key.
- At −4 dB the detector already finds nearly every frame, but only about half decode,
  so the decoder is the limit again. Coherent reception could in theory go ~3 dB lower.
  Candidates: forward-backward phase smoothing and a decision-directed CFO estimate over
  the whole frame.
- Several channels at once: at 20 Msps the HackRF covers four Zigbee channels, which a
  polyphase channelizer could split.

## License

[MIT](LICENSE)
