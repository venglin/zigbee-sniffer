"""Wireshark integration: PCAP streaming to stdout and the extcap interface."""

import re
import struct
import subprocess
import sys
from pathlib import Path

from zbdemod import extcap

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "examples" / "synthetic.cs8"


def pcap_records(data: bytes) -> tuple[int, list[bytes]]:
    """(linktype, packet payloads) of a little-endian PCAP byte string."""
    magic, _, _, _, _, _, linktype = struct.unpack_from("<IHHiIII", data, 0)
    assert magic == 0xA1B2C3D4
    pos, packets = 24, []
    while pos < len(data):
        _, _, incl, _ = struct.unpack_from("<IIII", data, pos)
        packets.append(data[pos + 16 : pos + 16 + incl])
        pos += 16 + incl
    assert pos == len(data)
    return linktype, packets


def test_pcap_to_stdout_streams_valid_pcap():
    res = subprocess.run(
        [sys.executable, "-m", "zbdemod", "file", str(SYNTHETIC), "--pcap", "-"],
        cwd=ROOT,
        capture_output=True,
        timeout=120,
    )
    assert res.returncode == 0, res.stderr
    linktype, packets = pcap_records(res.stdout)
    assert linktype == 283 and len(packets) == 7
    # Human-readable frame lines must not pollute the PCAP stream.
    assert b"Beacon Request" in res.stderr


def test_extcap_protocol_text():
    assert re.search(r"^interface \{value=zbdemod\}\{display=[^}]+\}$", extcap.interfaces_text(), re.M)
    assert extcap.interfaces_text().startswith("extcap {version=")
    assert "{number=283}" in extcap.dlts_text()
    cfg = extcap.config_text().splitlines()
    args = [line for line in cfg if line.startswith("arg ")]
    numbers = [int(re.search(r"\{number=(\d+)\}", a).group(1)) for a in args]
    assert numbers == list(range(len(args)))  # consecutive, as Wireshark expects
    for a in args:
        assert re.search(r"\{call=--[a-z]+\}", a) and re.search(r"\{type=[a-z]+\}", a)
    channel_values = [line for line in cfg if line.startswith("value {arg=0}")]
    assert len(channel_values) == 16 and sum("{default=true}" in v for v in channel_values) == 1
    # every option the dialog can pass is accepted by the capture parser
    calls = [re.search(r"\{call=(--[a-z]+)\}", a).group(1) for a in args]
    parser_opts = {s for act in extcap.build_parser()._actions for s in act.option_strings}
    assert set(calls) <= parser_opts


def test_extcap_main_answers_queries(capsys):
    assert extcap.main(["--extcap-interfaces", "--extcap-version=4.6"]) == 0
    assert "zbdemod" in capsys.readouterr().out
    assert extcap.main(["--extcap-dlts", "--extcap-interface", "zbdemod"]) == 0
    assert "283" in capsys.readouterr().out
    assert extcap.main(["--extcap-dlts", "--extcap-interface", "other"]) == 1


def test_extcap_capture_from_recording(tmp_path):
    fifo = tmp_path / "fifo.pcap"  # Wireshark passes a FIFO / named pipe; a file works the same
    rc = extcap.main(
        ["--capture", "--extcap-interface", "zbdemod", "--fifo", str(fifo), "--file", str(SYNTHETIC)]
    )
    assert rc == 0
    linktype, packets = pcap_records(fifo.read_bytes())
    assert linktype == 283 and len(packets) == 7


def test_extcap_install_and_uninstall(tmp_path, capsys):
    assert extcap.install(str(tmp_path)) == 0
    files = list(tmp_path.iterdir())
    assert len(files) == 1 and files[0].stem == "zbdemod-extcap"
    text = files[0].read_bytes().decode("utf-8", "replace")
    assert "-m zbdemod.extcap" in text and sys.executable in text
    assert extcap.install(str(tmp_path), uninstall=True) == 0
    assert list(tmp_path.iterdir()) == []


def test_wrapper_scripts_pass_all_arguments():
    win = extcap.wrapper_text(r"C:\py\python.exe", r"C:\src", windows=True)
    assert win.startswith("@echo off") and win.rstrip().endswith("%*") and "\r\n" in win
    posix = extcap.wrapper_text("/usr/bin/python3", "/src", windows=False)
    assert posix.startswith("#!/bin/sh") and 'exec "/usr/bin/python3" -m zbdemod.extcap "$@"' in posix
