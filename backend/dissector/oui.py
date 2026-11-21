"""Curated IEEE OUI MAC vendor lookup table for L2 Ethernet dissection."""
from __future__ import annotations

OUI_TABLE = {
    "00:00:0c": "Cisco",
    "00:01:42": "Cisco",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "00:03:ff": "Microsoft",
    "00:1c:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "02:42:ac": "Docker Container",
    "00:16:3e": "Xen Virtual",
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "f4:f5:d8": "Google",
    "00:1b:63": "Apple",
    "28:cf:da": "Apple",
    "3c:07:54": "Apple",
    "a4:83:e7": "Apple",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1b:21": "Intel",
    "00:1e:67": "Intel",
    "3c:97:0e": "Intel",
    "a8:2b:dd": "Intel/Realtek",
    "00:e0:4c": "Realtek",
    "52:54:ab": "Realtek",
    "00:e0:fc": "Huawei",
    "28:6e:d4": "Huawei",
    "48:46:fb": "Huawei",
    "14:cf:92": "TP-Link",
    "50:c7:bf": "TP-Link",
    "c0:25:e9": "TP-Link",
    "64:cc:2e": "Xiaomi",
    "28:6c:07": "Xiaomi",
    "00:14:22": "Dell",
    "d4:be:d9": "Dell",
    "18:03:73": "Dell",
    "00:17:a4": "Hewlett-Packard",
    "3c:d9:2b": "Hewlett-Packard",
    "00:21:cc": "Lenovo",
    "54:ee:75": "Lenovo",
    "00:09:0f": "Fortinet",
    "00:1c:73": "Arista",
    "00:25:90": "SuperMicro",
    "b4:2e:99": "Giga-Byte",
}


def lookup_oui(mac: str) -> str:
    mac_l = mac.lower()
    if mac_l == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"
    if mac_l.startswith("01:00:5e"):
        return "IPv4 Multicast"
    if mac_l.startswith("33:33:"):
        return "IPv6 Multicast"
    if mac_l == "00:00:00:00:00:00":
        return "Loopback/Unspecified"
    prefix = mac_l[:8]
    vendor = OUI_TABLE.get(prefix)
    if vendor:
        return vendor
    # Check locally administered bit
    try:
        first_byte = int(mac_l[:2], 16)
        if first_byte & 0x02:
            return "Locally Administered"
    except ValueError:
        pass
    return ""


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)
