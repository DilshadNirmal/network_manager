import os
import re
import sys
import socket
import struct
import psutil
import tempfile
import ipaddress
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Persists across calls — first-seen timestamp locks on first discovery.
_first_seen_cache = {}

# Lazily-loaded OUI → vendor map (from bundled nmap-mac-prefixes).
_oui_map = None


# ─── diagnostic logging ────────────────────────────────────────────────────────
# Windowed (--noconsole) builds have nowhere to print, so we also append to a
# log file. Look for network_dashboard.log next to the .exe (or in %TEMP%) to
# see exactly which interfaces/networks were scanned and how many hosts replied.

def _log_path():
    try:
        base = (os.path.dirname(sys.executable)
                if getattr(sys, "frozen", False)
                else os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, "network_dashboard.log")
        open(path, "a").close()          # writable?
        return path
    except Exception:
        return os.path.join(tempfile.gettempdir(), "network_dashboard.log")


def _log(msg):
    line = f"{datetime.now():%H:%M:%S}  {msg}"
    print(line)
    try:
        with open(_log_path(), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


# ─── bundled data directory ────────────────────────────────────────────────────

def _bundled_dir():
    """Directory holding bundled data files (works frozen or from source)."""
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(base, "bin")
    return candidate if os.path.isdir(candidate) else base


# ─── vendor / device-type lookup ─────────────────────────────────────────────

def _load_oui_map():
    """
    Parse the bundled nmap-mac-prefixes file into {OUI(6 hex upper): vendor}.

    This is the same OUI database nmap uses, but it's a plain text file — no
    nmap binary, Npcap, or admin rights required. Loaded once and cached.
    """
    global _oui_map
    if _oui_map is not None:
        return _oui_map

    _oui_map = {}
    path = os.path.join(_bundled_dir(), "nmap-mac-prefixes")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 6:
                    _oui_map[parts[0].upper()] = parts[1]
    except Exception:
        pass
    return _oui_map


def get_vendor(mac):
    """Look up the manufacturer for a MAC via the bundled OUI database."""
    if not mac or mac == "n/a":
        return "Unknown"
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return _load_oui_map().get(oui, "Unknown")


def get_device_type(vendor):
    """Best-effort device class from the vendor name (substring match)."""
    v = vendor.lower()
    if "local" in v:
        return "Computer"
    if any(k in v for k in ("apple",)):
        return "Apple Device"
    if any(k in v for k in ("samsung", "xiaomi", "oppo", "vivo", "realme",
                            "oneplus", "huawei", "motorola", "google")):
        return "Mobile"
    if any(k in v for k in ("dell", "msi", "asus", "lenovo", "hewlett",
                            "hp ", "acer", "gigabyte", "intel", "micro-star")):
        return "Computer"
    if any(k in v for k in ("tp-link", "tp link", "netgear", "d-link", "asus",
                            "cisco", "aruba", "ubiquiti", "mikrotik", "zyxel")):
        return "Router / AP"
    return "Unknown"


# ─── hostname resolution ──────────────────────────────────────────────────────

def get_hostname(ip):
    """
    Resolve hostname using:
      1. Reverse DNS
      2. Avahi (.local)
      3. DEVICE-xx fallback
    """

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]

        if hostname:
            return hostname.split(".")[0].upper()

    except Exception:
        pass

    # Avahi / mDNS
    try:
        result = subprocess.run(
            ["avahi-resolve-address", ip],
            capture_output=True,
            text=True,
            timeout=2
        )

        if result.returncode == 0:

            hostname = result.stdout.split()[1]

            hostname = hostname.replace(".local", "")

            return hostname.upper()

    except Exception:
        pass

    # Fallback
    return f"DEVICE-{ip.split('.')[-1]}"


def detect_operating_system(ip):

    """
    Detect the operating system using the SSH banner.

    Returns:
        Ubuntu
        Windows
        SSH Device
        Unknown
    """

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        if sock.connect_ex((ip,22)) != 0:

            sock.close()

            return "Unknown"

        banner = sock.recv(1024).decode(
            errors="ignore"
        ).lower()

        sock.close()

        if "ubuntu" in banner:

            return "Ubuntu"

        elif "openssh_for_windows" in banner:

            return "Windows"

        elif "windows" in banner:

            return "Windows"

        elif "openssh" in banner:

            return "SSH Device"

        else:

            return "Unknown"

    except socket.timeout:

        return "Unknown"

    except Exception:

        return "Unknown"


# ─── interface filtering: Wi-Fi & Ethernet only ───────────────────────────────

# Substrings that identify a VIRTUAL / VPN / non-physical adapter. Checked
# first, so e.g. "vEthernet" (Hyper-V) is excluded before "ethernet" matches.
_VIRTUAL_PATTERNS = (
    "loopback", "lo0",
    "vmware", "vmnet", "virtualbox", "vbox",
    "hyper-v", "hyper v", "vethernet",
    "tap", "tun", "tap-windows", "openvpn", "wireguard", "wg",
    "tailscale", "zerotier", "vpn", "wan miniport", "duct",
    "bluetooth", "docker", "veth", "virbr", "br-",
    "isatap", "teredo", "pseudo", "filter", "wsl",
    "local area connection*",  # Windows hidden virtual/WFP adapters
)

# Substrings / prefixes that identify a real Wi-Fi or Ethernet adapter.
_PHYSICAL_PATTERNS = ("wi-fi", "wifi", "wireless", "wlan", "ethernet")
_PHYSICAL_PREFIXES = ("eth", "en", "wl")  # Linux/BSD: eth0, enp3s0, wlan0, wlp...


def _is_physical_interface(iface):
    """True only for genuine Wi-Fi / Ethernet adapters."""
    name = iface.lower()

    # Exclude virtual / VPN / tunnel adapters first.
    if any(p in name for p in _VIRTUAL_PATTERNS):
        return False

    # Windows-style friendly names.
    if any(p in name for p in _PHYSICAL_PATTERNS):
        return True

    # Linux/BSD-style short device names.
    if any(name.startswith(p) for p in _PHYSICAL_PREFIXES):
        return True

    return False


def _primary_ipv4():
    """This machine's primary outbound IPv4 (the active Wi-Fi/Ethernet address).

    Uses a UDP socket to a public IP — no packets are actually sent, but the OS
    picks the source address of the default route. Works regardless of how the
    adapter is named or what language Windows runs in.
    """
    for probe in ("8.8.8.8", "1.1.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((probe, 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith(("127.", "169.254.")):
                    return ip
            finally:
                s.close()
        except Exception:
            continue
    return None


def _iface_for_ip(ip):
    """Return the interface name that holds the given IPv4 address, or None."""
    if not ip:
        return None
    for iface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET and snic.address == ip:
                return iface
    return None


def get_active_interfaces():
    """Names of UP physical Wi-Fi/Ethernet interfaces that have an IPv4 address."""
    active = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for iface in addrs:
        if not _is_physical_interface(iface):
            continue
        if iface in stats and not stats[iface].isup:
            continue
        has_ipv4 = any(
            snic.family == socket.AF_INET and not snic.address.startswith("169.254.")
            for snic in addrs[iface]
        )
        if has_ipv4:
            active.append(iface)

    # Fallback: the adapter holding the default-route IP is the real active
    # Wi-Fi/Ethernet link, even if its name didn't match our patterns (e.g.
    # localized Windows names like "Ethernet 2" → "Etherne…" or non-English).
    primary_iface = _iface_for_ip(_primary_ipv4())
    if primary_iface and primary_iface not in active:
        if not any(p in primary_iface.lower() for p in _VIRTUAL_PATTERNS):
            active.append(primary_iface)

    return active


def get_interface_network(iface):
    """Return the CIDR network string for an interface, or None on failure."""
    try:
        addrs = psutil.net_if_addrs().get(iface, [])
        ip = netmask = None
        for snic in addrs:
            if snic.family == socket.AF_INET:
                ip = snic.address
                netmask = snic.netmask
                break
        if ip and netmask:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
    except Exception:
        pass
    return None


# ─── this machine's own interfaces ─────────────────────────────────────────────

def _own_ipv4_macs():
    """Return {ipv4: mac} for this machine's active physical interfaces."""
    result = {}
    addrs = psutil.net_if_addrs()
    link_family = getattr(psutil, "AF_LINK", getattr(socket, "AF_PACKET", -1))

    # Consider physical-by-name interfaces plus the default-route adapter, so
    # this machine is listed even when its adapter name doesn't match.
    wanted = set(get_active_interfaces())
    primary_iface = _iface_for_ip(_primary_ipv4())
    if primary_iface:
        wanted.add(primary_iface)

    for iface in wanted:
        ip = mac = None
        for snic in addrs.get(iface, []):
            if snic.family == socket.AF_INET and not snic.address.startswith("169.254."):
                ip = snic.address
            elif snic.family == link_family:
                mac = (snic.address or "").lower().replace("-", ":")
        if ip:
            result[ip] = mac or "n/a"
    return result


def get_local_devices():
    """This machine, read straight from its own interfaces — no scan needed."""
    devices = []
    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    hostname = socket.gethostname().split(".")[0].upper()

    for ip, mac in _own_ipv4_macs().items():
        key = mac if mac != "n/a" else ip
        _first_seen_cache.setdefault(key, now)
        devices.append({
            "name":        f"{hostname} (THIS DEVICE)",
            "ip":          ip,
            "mac":         mac,
            "os":          detect_operating_system(ip),
            "vendor":      "Local Device",
            "device_type": "Computer",
            "status":      "ACTIVE",
            "first_seen":  _first_seen_cache[key],
            "last_seen":   now,
        })
    return devices


# ─── ping sweep (populates the OS ARP cache) ───────────────────────────────────

def _ping(ip):
    """Fire a single ping at ip.

       We don't care about the result,
       only that the OS performs ARP resolution
       and caches the MAC.
    """
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        subprocess.run(cmd, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _hosts_for(network):
    """List of host IP strings for a CIDR, or [] if too large / invalid."""
    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except Exception:
        return []
    hosts = [str(h) for h in net.hosts()]
    return hosts if 0 < len(hosts) <= 1024 else []   # skip huge / non-LAN ranges


# ─── Windows host discovery (ctypes → iphlpapi, no subprocess / Npcap / admin) ──
# Strategy: IcmpSendEcho every host with a short timeout (parallel) to provoke
# ARP resolution — this caches each live host's MAC even when the host blocks
# ICMP, because ARP happens before the echo is sent. Then read the whole ARP
# cache with GetIpNetTable. IcmpSendEcho has a hard timeout, so dead hosts can't
# stall the scan (unlike SendARP, which can serialise for seconds per dead host).

_winapi = None


def _init_winapi():
    global _winapi
    if _winapi is not None:
        return _winapi
    import ctypes
    iph = ctypes.windll.iphlpapi
    ws2 = ctypes.windll.ws2_32
    ws2.inet_addr.argtypes = [ctypes.c_char_p]
    ws2.inet_addr.restype = ctypes.c_uint32
    iph.IcmpCreateFile.restype = ctypes.c_void_p
    iph.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    iph.IcmpSendEcho.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_ushort,
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong,
    ]
    iph.IcmpSendEcho.restype = ctypes.c_ulong
    _winapi = (ctypes, iph, ws2)
    return _winapi


def _icmp_ping(ip, timeout_ms=300):
    """Provoke ARP resolution for ip via a single ICMP echo (bounded timeout)."""
    try:
        ctypes, iph, ws2 = _init_winapi()
        dest = ws2.inet_addr(ip.encode("ascii"))
        if dest in (0, 0xFFFFFFFF):
            return
        handle = iph.IcmpCreateFile()
        if not handle:
            return
        data = b"abcdefghijklmnop"
        reply = ctypes.create_string_buffer(len(data) + 64)
        iph.IcmpSendEcho(handle, dest, data, len(data), None,
                         reply, len(reply), timeout_ms)
        iph.IcmpCloseHandle(handle)
    except Exception:
        pass


def _windows_arp_cache():
    """Read the full OS ARP cache via GetIpNetTable (ctypes, no subprocess)."""
    found = {}
    try:
        ctypes, iph, _ = _init_winapi()

        class _ROW(ctypes.Structure):
            _fields_ = [("dwIndex", ctypes.c_ulong),
                        ("dwPhysAddrLen", ctypes.c_ulong),
                        ("bPhysAddr", ctypes.c_ubyte * 8),
                        ("dwAddr", ctypes.c_ulong),
                        ("dwType", ctypes.c_ulong)]

        size = ctypes.c_ulong(0)
        iph.GetIpNetTable(None, ctypes.byref(size), 0)      # query needed size
        if size.value == 0:
            return found
        buf = (ctypes.c_ubyte * size.value)()
        if iph.GetIpNetTable(buf, ctypes.byref(size), 0) != 0:
            return found

        num = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong))[0]

        class _TABLE(ctypes.Structure):
            _fields_ = [("dwNumEntries", ctypes.c_ulong), ("table", _ROW * num)]

        tbl = ctypes.cast(buf, ctypes.POINTER(_TABLE))[0]
        for i in range(tbl.dwNumEntries):
            row = tbl.table[i]
            if row.dwPhysAddrLen != 6 or row.dwType == 2:   # 2 = invalid/incomplete
                continue
            ip = socket.inet_ntoa(struct.pack("<I", row.dwAddr))
            mac = ":".join("%02x" % b for b in row.bPhysAddr[:6])
            if _is_real_unicast(ip, mac):
                found[ip] = mac
    except Exception:
        pass
    return found


def _discover(network):
    """Return {ip: mac} for live hosts on the given CIDR network."""
    hosts = _hosts_for(network)
    found = {}

    if sys.platform == "win32":
        # Active probe: ICMP-echo every host (bounded timeout) to fill the ARP
        # cache — even ICMP-blocked hosts get cached because ARP runs first.
        if hosts:
            with ThreadPoolExecutor(max_workers=min(128, len(hosts))) as pool:
                list(pool.map(_icmp_ping, hosts))
        # Read the resulting ARP cache for IP→MAC pairs.
        found.update(_windows_arp_cache())
        return found

    # Linux / Unix: ping-sweep fills the kernel ARP cache, then read it.
    if hosts:
        with ThreadPoolExecutor(max_workers=min(128, len(hosts))) as pool:
            list(pool.map(_ping, hosts))
    for ip, mac in get_arp_table().items():
        found[ip] = mac
    return found


# ─── ARP table parsing (IP → MAC, no special privileges) ───────────────────────

def _normalize_mac(raw):
    mac = raw.lower().replace("-", ":")
    return mac if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) else None


def _is_real_unicast(ip, mac):
    """Reject broadcast / multicast / null entries."""
    if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    if mac.startswith(("01:00:5e", "33:33", "01:80:c2")):  # multicast
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            return False
        if ip.endswith(".255"):
            return False
    except Exception:
        return False
    return True


def get_arp_table():
    """Return {ip: mac} from the OS ARP cache. Cross-platform, no privileges."""
    table = {}

    # Linux: /proc/net/arp is fast and structured.
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as fh:
                next(fh, None)  # header
                for line in fh:
                    cols = line.split()
                    if len(cols) >= 4:
                        ip, mac = cols[0], _normalize_mac(cols[3])
                        if mac and _is_real_unicast(ip, mac):
                            table[ip] = mac
            return table
        except Exception:
            pass

    # Windows / macOS / fallback: parse `arp -a`.
    try:
        flags = 0x08000000 if sys.platform == "win32" else 0
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10, creationflags=flags).stdout
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-]"
                          r"[0-9a-fA-F:-]{14,})", line)
            if m:
                ip, mac = m.group(1), _normalize_mac(m.group(2))
                if mac and _is_real_unicast(ip, mac):
                    table[ip] = mac
    except Exception:
        pass
    return table


# ─── main scan ───────────────────────────────────────────────────────────────

def scan_network(progress_callback=None):
    """
    Discover devices on the local Wi-Fi / Ethernet network(s).

    Pure Python: a concurrent ping-sweep fills the OS ARP cache, then the ARP
    cache is read for IP→MAC pairs. No nmap, no Npcap, no admin rights — so it
    runs unchanged on any machine.
    """
    devices = []
    if progress_callback:
        progress_callback(5,"Loading Network Scanner...")
    seen = set()
    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    _log(f"=== scan start (platform={sys.platform}, frozen={getattr(sys,'frozen',False)}) ===")
    _log(f"primary IP = {_primary_ipv4()}")
    all_ifaces = list(psutil.net_if_addrs().keys())
    _log(f"all interfaces: {all_ifaces}")

    interfaces = get_active_interfaces()
    if progress_callback:
        progress_callback(10, "Loading Network Module...")

    if progress_callback:
        progress_callback(20, "Detecting Interfaces...")
    _log(f"selected Wi-Fi/Ethernet interfaces: {interfaces}")
    if not interfaces:
        _log("No active Wi-Fi/Ethernet interface found — showing this device only.")
        return get_local_devices()

    # Networks belonging to *our* physical interfaces — used to keep only LAN
    # devices and drop anything an ARP entry might carry from another adapter.
    own_networks = []
    discovered = {}
    total_interfaces = len(interfaces)
    current_interface = 0
    for iface in interfaces:
        current_interface += 1

        if progress_callback:

           progress = 20 + int((current_interface / total_interfaces) * 20)

           progress_callback(progress,f"Scanning {iface}...")

        network = get_interface_network(iface)
        if not network:
            _log(f"  {iface}: could not resolve network — skipped")
            continue
        _log(f"Scanning {network} on {iface} ...")
        try:
            own_networks.append(ipaddress.IPv4Network(network, strict=False))
        except Exception:
            pass
        found = _discover(network)
        if progress_callback:

           progress_callback(50,"Discovering Network Devices...")
        _log(f"  {iface}: {len(found)} host(s) in ARP cache after probe")
        discovered.update(found)

    def _in_own_networks(ip):
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in own_networks)
        except Exception:
            return False

    # Bound reverse-DNS so hosts without a PTR record can't stall the scan.
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(0.6)
    try:
        device_total = len(discovered)
        device_index = 0
        os_results={}
        with ThreadPoolExecutor(max_workers=20) as executor:

             futures = {}

             for ip in discovered.keys():

                 futures[ip] = executor.submit(detect_operating_system,ip)

             for ip, future in futures.items():

                 try:

                    os_results[ip] = future.result()

                 except Exception:

                        os_results[ip] = "Unknown"


        hostname_results = {}

        with ThreadPoolExecutor(max_workers=64) as executor:

             futures = {}

             for ip in discovered.keys():

                 futures[ip] = executor.submit(get_hostname,ip)

             for ip, future in futures.items():

                 try:

                   hostname_results[ip] = future.result()

                 except Exception:

                   hostname_results[ip] = f"DEVICE-{ip.split('.')[-1]}"


        for ip, mac in discovered.items():
            device_index += 1

            if progress_callback and device_total > 0:

               progress = 50 + int((device_index / device_total) * 35)

               if progress < 60:

                  progress_callback(progress, "Resolving Hostnames...")

               elif progress < 70:

                  progress_callback(progress, "Collecting MAC Addresses...")

               elif progress < 80:

                  progress_callback(progress, "Identifying Device Vendor...")

               else:

                  progress_callback(progress, "Building Device Database...")
            if not _in_own_networks(ip) or mac in seen:
                continue
            seen.add(mac)

            vendor = get_vendor(mac)
            hostname = hostname_results[ip]
            operating_system = os_results[ip]
            devices.append({
                "name":        hostname,
                "ip":          ip,
                "mac":         mac,
                "os":          operating_system,
                "vendor":      vendor,
                "device_type": get_device_type(vendor),
                "status":      "ACTIVE",
                "first_seen":  _first_seen_cache.setdefault(mac, now),
                "last_seen":   now,
            })
            if progress_callback:

               progress_callback(
        progress,
        f"DEVICE_COUNT:{len(devices)}"
    )
    finally:
        socket.setdefaulttimeout(old_timeout)

    # Always include this machine (the gateway/router won't ARP-cache ourselves).
    if progress_callback:

       progress_callback(90,"Building Device Database...")
    for local in get_local_devices():
        if progress_callback:
           progress_callback(95,f"DEVICE_COUNT:{len(devices)}")
        if not any(d["mac"] == local["mac"] for d in devices):
            devices.append(local)
        else:
            for d in devices:
                if d["mac"] == local["mac"]:
                    d.update(name=local["name"], vendor="Local Device",
                             device_type="Computer")
    if progress_callback:

       progress_callback(95,"Generating Dashboard...")
    devices.sort(key=lambda d: tuple(map(int, d["ip"].split("."))))
    _log(f"Total: {len(devices)} device(s)\n")
    if progress_callback:

       progress_callback(100,"Loading Complete")
    return devices


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    found = scan_network()
    print(f"\nFound {len(found)} devices\n")
    for d in found:
        print(f"{d['ip']:15}  {d['mac']:17}  {d['name']:28}  {d['vendor']}")
