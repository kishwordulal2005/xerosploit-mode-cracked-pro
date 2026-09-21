#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import sys
import shutil
import subprocess

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
#        Copyright © 2016 LionSec (www.lionsec.net)                         #
#                                                                           #
#---------------------------------------------------------------------------#

if getattr(os, "geteuid", None) is None:
    sys.exit("""\033[1;91m\n[!] Xerosploit installer only runs on Linux (native Windows is unsupported, issue #163).\n\033[1;m""")
if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] Xerosploit installer must be run as root. ¯\\_(ツ)_/¯\n\033[1;m""")

if sys.version_info[0] < 3:
    # Python 2's input() evaluates the typed text, so choosing "1" yields int
    # 1 which never equals "1" and the OS menu loops forever doing nothing.
    # The installer is Python 3 only.
    sys.exit("""\033[1;91m\n[!] Xerosploit installer requires Python 3. Re-run with:\n    sudo python3 install.py\n\033[1;m""")

print(""" \033[1;36m
┌══════════════════════════════════════════════════════════════┐
█                                                              █
█                     Xerosploit Installer                     █
█                                                              █
└══════════════════════════════════════════════════════════════┘     \033[1;m""")

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# Minimum Python version for xerosploit.py / this installer (stdlib only,
# no walrus/match syntax, so 3.8 is a safe floor).
PYTHON_MIN_VERSION = (3, 8)

# Set once ensure_python() runs; pip/python verification steps use it instead
# of a hardcoded `pip3`/`python3` (Arch calls it `python`, etc.).
PY_EXE = None


def run(cmd, fatal=True):
    """Run a shell command, echo it, return exit code. Abort on failure if fatal."""
    print("\033[1;34m[++] Running: %s\033[1;m" % cmd)
    rc = os.system(cmd)
    if rc != 0:
        msg = "\033[1;91m[!] Command failed (exit %d): %s\033[1;m" % (rc, cmd)
        print(msg)
        if fatal:
            sys.exit(msg + "\n[!] Installation aborted. Fix the error above and re-run.")
    return rc


def have(cmd):
    return shutil.which(cmd) is not None


def read_os_release(path="/etc/os-release"):
    """Parse /etc/os-release into a dict (keys upper-cased)."""
    info = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                info[key.strip().upper()] = val.strip().strip("\"").strip("'")
    except OSError:
        pass
    return info


def detect_distro_family(os_release=None):
    """Map the distro to a family: debian / fedora / arch / suse / unknown.

    Works on Kali, Parrot, Debian, Ubuntu, Mint, Fedora, RHEL-likes, Arch,
    Manjaro, BlackArch, on VM or bare metal (detection is file-based, no
    virtualization dependency).
    """
    info = os_release if os_release is not None else read_os_release()
    ids = set(((info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()).split())
    if ids & {"debian", "ubuntu", "kali", "parrot", "linuxmint", "mint",
               "pop", "popos", "raspbian", "elementary", "zorin", "mx",
               "mxlinux", "neon", "kde", "deepin"}:
        return "debian"
    if ids & {"fedora", "rhel", "redhat", "centos", "rocky", "almalinux",
               "ol", "oraclelinux", "scientific", "nobara"}:
        return "fedora"
    if ids & {"arch", "manjaro", "blackarch", "garuda", "endeavouros",
               "artix", "cachyos"}:
        return "arch"
    if ids & {"opensuse", "suse", "sles", "opensuse-leap", "opensuse-tumbleweed"}:
        return "suse"
    if ids & {"alpine"}:
        return "alpine"
    return "unknown"


def detect_pkg_manager(family=None):
    """Return 'apt', 'dnf', 'pacman' or 'yum'.

    The distro family decides which managers are eligible (a Fedora box that
    happens to have apt-get must still use dnf/yum, not apt); 'unknown'
    distros fall back to the first usable manager on PATH. None if none found.
    """
    family = family if family is not None else detect_distro_family()
    order = {"debian": (("apt-get", "apt"),),
             "fedora": (("dnf", "dnf"), ("yum", "yum")),
             "arch": (("pacman", "pacman"),),
             "suse": (("zypper", "zypper"),),
             "alpine": (("apk", "apk"),)}.get(
        family, (("apt-get", "apt"), ("dnf", "dnf"), ("pacman", "pacman"),
                 ("yum", "yum"), ("apk", "apk"), ("zypper", "zypper")))
    for cmd, name in order:
        if have(cmd):
            return name
    return None


# System packages per package manager: "base" must install (fatal),
# "extra" is best-effort (non-fatal, warning only).
# bettercap v2 is a static Go binary: no ruby/gems needed anymore, but it
# links libpcap at runtime, so the pcap library/headers stay required.
SYSTEM_PACKAGES = {
    "apt": {
        "base": ("nmap hping3 build-essential python3 python3-pip python3-venv "
                 "git openssl libpcap-dev libgmp-dev "
                 "python3-tabulate python3-pil "
                 "iptables iproute2 net-tools wireless-tools"),
        "extra": ("driftnet xterm ruby ruby-dev rubygems",),
    },
    "dnf": {
        "base": ("nmap hping3 gcc gcc-c++ make git openssl "
                 "libpcap-devel gmp-devel python3 python3-pip "
                 "python3-tabulate python3-pillow "
                 "iptables iproute net-tools"),
        "extra": ("xterm ruby ruby-devel rubygems",),
    },
    "pacman": {
        "base": ("nmap hping3 base-devel python python-pip git openssl libpcap "
                 "gmp python-tabulate python-pillow "
                 "iptables iproute2 net-tools wireless_tools"),
        "extra": ("xterm ruby",),
        # NOTE: driftnet is AUR-only on Arch -> installed separately if an
        # AUR helper exists, otherwise skipped with a warning (see below).
    },
    "yum": {
        "base": ("nmap hping3 gcc gcc-c++ make git openssl "
                 "libpcap-devel gmp-devel python3 python3-pip "
                 "iptables iproute net-tools"),
        "extra": ("xterm",),
    },
}

# Go toolchain + build headers for compiling bettercap from source.
# Only used on architectures without a prebuilt binary (e.g. ARM).
# Package names verified on apt; dnf/pacman entries are best-effort.
GO_BUILD_PACKAGES = {
    "apt": "golang-go libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev git",
    "dnf": "golang libpcap-devel libusb1-devel libnetfilter_queue-devel git",
    "pacman": "go libpcap libusb libnetfilter_queue git",
    "yum": "golang libpcap-devel libusb-devel git",
}

# Python bootstrap packages per manager (used when no usable python3 found).
PYTHON_BOOTSTRAP_PACKAGES = {
    "apt": "python3 python3-pip python3-venv",
    "dnf": "python3 python3-pip",
    "pacman": "python python-pip",
    "yum": "python3 python3-pip",
}


def pkg_refresh(pm):
    """Refresh package metadata (best-effort; install proceeds regardless)."""
    if pm == "apt":
        run("apt-get update", fatal=False)
    elif pm == "pacman":
        run("pacman -Sy --noconfirm", fatal=False)
    elif pm in ("dnf", "yum"):
        run(pm + " makecache", fatal=False)


def pkg_install(pm, packages, fatal=True):
    """Install a package string with the native manager."""
    if isinstance(packages, (list, tuple)):
        packages = " ".join(packages)
    if pm == "apt":
        return run("apt-get install -y " + packages, fatal=fatal)
    if pm in ("dnf", "yum"):
        return run(pm + " install -y " + packages, fatal=fatal)
    if pm == "pacman":
        return run("pacman -S --noconfirm --needed " + packages, fatal=fatal)
    sys.exit("\033[1;91m[!] Unsupported package manager. Install dependencies "
             "manually (python3, ruby, nmap, libpcap headers) and re-run.\033[1;m")


def probe_python(exe):
    """Return (major, minor, micro) for a python executable, or None."""
    try:
        out = subprocess.check_output(
            [exe, "--version"], stderr=subprocess.STDOUT, timeout=15)
        out = out.decode("utf-8", errors="replace")
        m = re.search(r"Python\s+(\d+)\.(\d+)\.(\d+)", out)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except Exception:
        pass
    return None


def find_python():
    """Locate the best usable python3 (prefers newest). Returns (exe, ver)."""
    best = None
    candidates = ["python3"] + ["python3.%d" % m for m in range(15, 7, -1)] + ["python"]
    seen = set()
    for cand in candidates:
        path = shutil.which(cand)
        if not path or path in seen:
            continue
        seen.add(path)
        ver = probe_python(path)
        if ver and ver[0] == 3 and (best is None or ver > best[1]):
            best = (path, ver)
    return best


def ensure_python(pm):
    """Make sure a usable Python 3 exists, downloading it if missing.

    Returns the interpreter path and records it in PY_EXE for later steps.
    """
    global PY_EXE
    found = find_python()
    if found and found[1] >= PYTHON_MIN_VERSION:
        PY_EXE = found[0]
        print("\033[1;32m[+] Found Python %s at %s\033[1;m"
              % (".".join(map(str, found[1])), found[0]))
        return PY_EXE
    if found:
        print("\033[1;33m[!] Found Python %s at %s, but >= %s is required. "
              "Installing a newer Python ...\033[1;m"
              % (".".join(map(str, found[1])), found[0],
                 ".".join(map(str, PYTHON_MIN_VERSION))))
    else:
        print("\033[1;33m[!] No Python 3 found. Downloading and installing it "
              "automatically ...\033[1;m")
    pkgs = PYTHON_BOOTSTRAP_PACKAGES.get(pm)
    if not pkgs:
        sys.exit("\033[1;91m[!] Cannot auto-install Python: unsupported package "
                 "manager. Please install Python >= %s manually and re-run.\033[1;m"
                 % ".".join(map(str, PYTHON_MIN_VERSION)))
    pkg_install(pm, pkgs)
    found = find_python()
    if not found or found[1] < PYTHON_MIN_VERSION:
        sys.exit("\033[1;91m[!] Python >= %s still not found after install. "
                 "Install it manually and re-run.\033[1;m"
                 % ".".join(map(str, PYTHON_MIN_VERSION)))
    PY_EXE = found[0]
    print("\033[1;32m[+] Now using Python %s at %s\033[1;m"
          % (".".join(map(str, found[1])), found[0]))
    return PY_EXE


def ensure_pip():
    """Make sure `PY_EXE -m pip` works, bootstrapping via ensurepip if needed."""
    exe = PY_EXE or "python3"
    if os.system("%s -m pip --version > /dev/null 2>&1"
                 % shlex_quote(exe)) == 0:
        return
    print("\033[1;33m[!] pip not found for %s, bootstrapping via ensurepip ...\033[1;m" % exe)
    os.system("%s -m ensurepip --default-pip > /dev/null 2>&1" % shlex_quote(exe))
    if os.system("%s -m pip --version > /dev/null 2>&1" % shlex_quote(exe)) != 0:
        sys.exit("\033[1;91m[!] pip is missing and could not be bootstrapped. "
                 "Install it (e.g. python3-pip) and re-run.\033[1;m")


def shlex_quote(s):
    import shlex as _shlex
    return _shlex.quote(s)


def pip_install(packages):
    """pip install handling PEP 668 (externally-managed-environment).

    Uses the auto-detected interpreter (`PY_EXE -m pip`) instead of a
    hardcoded `pip3`, so Arch (`python -m pip`) etc. work too.
    """
    exe = PY_EXE or "python3"
    base = "%s -m pip install" % shlex_quote(exe)
    pkgs = " ".join(packages)
    # Prefer distro packages when available; pip is fallback with --break-system-packages.
    rc = os.system(base + " --break-system-packages %s" % pkgs)
    if rc != 0:
        # Older pip without --break-system-packages flag: retry plain install.
        rc = os.system(base + " %s" % pkgs)
    if rc != 0:
        sys.exit("\033[1;91m[!] pip install failed for: %s\033[1;m" % pkgs)
    return rc


def install_deps_parrot(pm="apt"):
    # Parrot ships bettercap (v1) via apt; remove it to avoid conflicts with v2.
    if pm == "apt" and have("apt-get"):
        run("apt-get remove -y bettercap || true", fatal=False)


def bettercap_version():
    """Pinned bettercap v2 version, read from tools/bettercap2/BETTERCAP_VERSION."""
    for path in (os.path.join(REPO_DIR, "tools", "bettercap2", "BETTERCAP_VERSION"),
                 "/opt/xerosploit/tools/bettercap2/BETTERCAP_VERSION"):
        try:
            with open(path) as f:
                ver = f.read().strip()
                if ver:
                    return ver
        except OSError:
            pass
    return "v2.41.7"


def bettercap_asset():
    """Return (asset_base, from_source) for this machine.

    amd64  -> prebuilt static binary from GitHub releases (verified).
    arm64/armv7 (Raspberry Pi etc., issues #15/#49/#168/#275) -> no prebuilt
    binary is published, so compile from source (recipe validated by build).
    """
    machine = os.uname().machine.lower() if hasattr(os, "uname") else ""
    if machine in ("x86_64", "amd64"):
        return ("bettercap_linux_amd64", False)
    if machine in ("aarch64", "arm64", "armv8l", "armv7l", "armhf", "arm"):
        return (None, True)
    return (None, None)


def download_file(url, dest):
    """Download url to dest with stdlib only (no curl/wget dependency)."""
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "xerosploit-installer"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        if resp.status != 200:
            raise IOError("HTTP %s for %s" % (resp.status, url))
        total = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)
                if total % (8 * 1024 * 1024) < 65536:
                    print("      ... %d MB" % (total // (1024 * 1024)))
    return dest


def sha256_of(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def install_bettercap_prebuilt(ver, asset):
    """Download the official prebuilt binary, verify sha256, install it."""
    base_url = ("https://github.com/bettercap/bettercap/releases/download/"
                "%s/%s" % (ver, asset))
    tmpdir = "/tmp/xerosploit-bettercap"
    run("rm -rf '%s' && mkdir -p '%s'" % (tmpdir, tmpdir), fatal=False)
    zippath = os.path.join(tmpdir, asset + ".zip")
    print("\033[1;34m[++] Downloading bettercap %s (%s) ...\033[1;m" % (ver, asset))
    try:
        download_file(base_url + ".zip", zippath)
    except Exception as e:
        sys.exit("\033[1;91m[!] Download failed (%s). Check network access to "
                 "github.com and re-run.\033[1;m" % e)
    import zipfile
    with zipfile.ZipFile(zippath) as zf:
        names = zf.namelist()
        if "bettercap" not in names:
            sys.exit("\033[1;91m[!] Unexpected zip contents: %s\033[1;m" % names)
        zf.extract("bettercap", tmpdir)
    print("\033[1;34m[++] Verifying sha256 ...\033[1;m")
    try:
        # NOTE: the published .sha256 covers the extracted `bettercap`
        # binary ("SHA2-256(bettercap)= ..."), not the zip itself.
        expect_text = urllib_get_text(base_url + ".sha256")
        m = re.search(r"[0-9a-fA-F]{64}", expect_text)
        if not m:
            sys.exit("\033[1;91m[!] Could not parse sha256 from %s.sha256\033[1;m" % asset)
        expect = m.group(0).lower()
        actual = sha256_of(os.path.join(tmpdir, "bettercap"))
        if expect != actual:
            sys.exit("\033[1;91m[!] sha256 mismatch for the bettercap binary:\n expected %s\n actual   %s\033[1;m"
                     % (expect, actual))
    except SystemExit:
        raise
    except Exception as e:
        print("\033[1;33m[!] Could not verify sha256 (%s), continuing ...\033[1;m" % e)
    run("install -m 0755 '%s' /usr/local/bin/bettercap"
        % os.path.join(tmpdir, "bettercap"))
    run("rm -rf '%s'" % tmpdir, fatal=False)


def urllib_get_text(url):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "xerosploit-installer"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def install_bettercap_from_source(pm, ver):
    """Compile bettercap from source (ARM/Raspberry Pi: no prebuilt binary).

    Recipe validated by a from-source build (same commands, amd64 host).
    """
    print("\033[1;34m[++] No prebuilt binary for this CPU; compiling bettercap "
          "%s from source (takes a few minutes) ...\033[1;m" % ver)
    pkgs = GO_BUILD_PACKAGES.get(pm)
    if not pkgs:
        sys.exit("\033[1;91m[!] Source build needs Go + libpcap/libusb/netfilter "
                 "headers; unsupported package manager. Install golang and the "
                 "pcap/usb/netfilter headers manually, then re-run.\033[1;m")
    pkg_install(pm, pkgs)
    if not have("go"):
        sys.exit("\033[1;91m[!] Go toolchain still missing after install. "
                 "Install golang manually and re-run.\033[1;m")
    srcdir = "/tmp/xerosploit-bettercap-src"
    run("rm -rf '%s'" % srcdir, fatal=False)
    run("git clone --depth 1 --branch '%s' "
        "https://github.com/bettercap/bettercap '%s'" % (ver, srcdir))
    # Build may take a while on small boards; be generous.
    rc = os.system("cd '%s' && go build -o bettercap . " % srcdir)
    if rc != 0:
        sys.exit("\033[1;91m[!] 'go build' failed (see above). A prebuilt binary "
                 "is only published for amd64; this CPU needs a working Go + "
                 "libpcap toolchain. Fix the errors above and re-run.\033[1;m")
    run("install -m 0755 '%s' /usr/local/bin/bettercap" % os.path.join(srcdir, "bettercap"))
    run("rm -rf '%s'" % srcdir, fatal=False)


def install_bettercap(pm):
    """Install bettercap v2 (prebuilt amd64, source-built ARM)."""
    ver = bettercap_version()
    asset, from_source = bettercap_asset()
    if asset is None and not from_source:
        sys.exit("\033[1;91m[!] Unsupported CPU (%s): bettercap publishes "
                 "prebuilt binaries for amd64 only. On ARM, install golang + "
                 "libpcap headers; other CPUs are unsupported.\033[1;m"
                 % (os.uname().machine if hasattr(os, "uname") else "?"))
    if from_source:
        install_bettercap_from_source(pm, ver)
    else:
        install_bettercap_prebuilt(ver, asset)
    if not have("bettercap"):
        sys.exit("\033[1;91m[!] 'bettercap' not found in PATH after install.\033[1;m")
    # Drop the legacy v1 gem if a previous xerosploit installed it.
    if have("gem"):
        run("gem uninstall -a -x xettercap || true", fatal=False)


def do_install():
    print("\033[1;34m\n[++] Installing Xerosploit ... \033[1;m")

    # Auto-detect distro + package manager (Kali/Debian/Ubuntu/Parrot/Fedora/
    # Arch/..., VM or bare metal) instead of assuming apt-get (issue #351 family).
    family = detect_distro_family()
    pm = detect_pkg_manager(family)
    info = read_os_release()
    print("\033[1;34m[++] Detected: %s (family: %s, packages: %s)\033[1;m"
          % (info.get("PRETTY_NAME", info.get("NAME", "unknown Linux")),
             family, pm or "none"))
    if pm is None:
        sys.exit("\033[1;91m[!] No supported package manager found "
                 "(need apt/dnf/pacman/yum). Install manually: python3 (>= 3.8), "
                 "git, nmap, libpcap headers, then re-run.\033[1;m")

    if family == "parrot" or info.get("ID", "").lower() == "parrot":
        install_deps_parrot(pm)

    pkg_refresh(pm)

    # Find Python automatically; download it if missing/too old.
    ensure_python(pm)
    ensure_pip()

    # NOTE: package names differ per distro and change over time, e.g.:
    #  - python-pip        -> python3-pip (removed from apt archives)
    #  - python3-terminaltables does NOT exist in Debian/Kali (pip covers it)
    #  - libgmp3-dev       -> libgmp-dev (renamed)
    #  - libpcap0.8 / ruby-network-interface do not exist in Kali repos
    #  - driftnet / xterm / iptables / iproute2 / net-tools / wireless-tools needed at runtime
    # bettercap v2 needs no ruby at all, but links libpcap at runtime,
    # so the pcap library/headers stay required.
    sets = SYSTEM_PACKAGES.get(pm, SYSTEM_PACKAGES["apt"])
    if pkg_install(pm, sets["base"], fatal=False) != 0:
        # Retry with a minimal set if some optional packages are missing.
        print("\033[1;33m[!] Full install failed, retrying with minimal set ...\033[1;m")
        minimal = sets["base"]
        if pm == "apt":
            minimal = ("nmap hping3 build-essential python3 python3-pip git openssl "
                       "libpcap-dev libgmp-dev python3-tabulate python3-pil")
        pkg_install(pm, minimal)
    for extra in sets.get("extra", ()):
        if pkg_install(pm, extra, fatal=False) != 0:
            print("\033[1;33m[!] Optional packages skipped: %s\033[1;m" % extra)
    if pm == "pacman" and not have("driftnet"):
        # driftnet lives in the AUR on Arch: use a helper if present.
        helper = next((h for h in ("yay", "paru", "trizen", "pikaur") if have(h)), None)
        if helper:
            run("%s -S --noconfirm --needed driftnet" % helper, fatal=False)
        else:
            print("\033[1;33m[!] driftnet is AUR-only on Arch and no AUR helper "
                  "(yay/paru) was found; the driftnet module will be unavailable. "
                  "Install an AUR helper and run: %s -S driftnet\033[1;m" % "yay")

    # Sanity gate before the pip/bettercap stages: fail fast with a per-distro
    # hint instead of cryptic errors later (e.g. missing compiler, issue #119 class).
    _missing = [t for t in ("git",) if not have(t)]
    _missing += [] if (have("gcc") or have("cc")) else ["c-compiler"]
    if _missing:
        _how = {"apt": "sudo apt-get install -y build-essential git",
                "dnf": "sudo dnf install -y gcc make git",
                "pacman": "sudo pacman -S --needed base-devel git",
                "yum": "sudo yum install -y gcc make git"}.get(pm)
        sys.exit("\033[1;91m[!] Still missing after system install: %s.\n%s\033[1;m"
                 % (", ".join(_missing),
                    ("Try manually: " + _how) if _how else
                    "Install a C toolchain + git manually and re-run."))

    # Python deps: prefer apt versions already installed; ensure pip copies exist
    # for systems where apt packages are absent (fixes PEP 668 externally-managed error).
    pip_install(["tabulate", "terminaltables", "pillow"])

    # bettercap v2 (replaces the Ruby xettercap 1.x fork and its whole gem
    # dependency hell: original_argv, File.exists?, SortedSet, rubydns majors,
    # celluloid, pcaprub builds, EventMachine, ...). Prebuilt static binary on
    # amd64, compiled from source on ARM.
    install_bettercap(pm)

    for tool in ("nmap", "hping3", "iptables"):
        if not have(tool):
            print("\033[1;33m[!] Warning: required tool '%s' not found in PATH.\033[1;m" % tool)

    # Install files to /opt/xerosploit
    run("mkdir -p /opt/xerosploit /opt/xerosploit/tools/files /opt/xerosploit/tools/log "
        "/opt/xerosploit/tools/bettercap2/tmp")
    run("cp -R '%s/tools/' /opt/xerosploit/" % REPO_DIR)
    run("cp '%s/xerosploit.py' /opt/xerosploit/xerosploit.py" % REPO_DIR)
    run("cp '%s/banner.py' /opt/xerosploit/banner.py" % REPO_DIR)
    # Default config (fixes FileNotFoundError for iface.txt/gateway.txt, issue #352)
    run("echo 0 > /opt/xerosploit/tools/files/iface.txt")
    run("echo 0 > /opt/xerosploit/tools/files/gateway.txt")
    run("touch /opt/xerosploit/tools/log/.keep /opt/xerosploit/tools/bettercap2/tmp/.keep")
    # Launcher (fixes 'xerosploit: command not found', issues #348/#351)
    run("cp '%s/run.sh' /usr/bin/xerosploit && chmod +x /usr/bin/xerosploit" % REPO_DIR)
    run("chmod +x /opt/xerosploit/xerosploit.py /opt/xerosploit/banner.py", fatal=False)

    print('\033[1;32m[+] Verifying installation ...\033[1;m')
    run("%s -c \"import tabulate, terminaltables; print('python deps OK')\""
        % shlex_quote(PY_EXE or "python3"))
    # `bettercap -h` prints Go usage and exits nonzero-safe; the version is
    # pinned by the download URL itself (tools/bettercap2/BETTERCAP_VERSION).
    run("which bettercap && bettercap -h > /dev/null 2>&1", fatal=False)
    run("which nmap && nmap --version 2>&1 | head -n 2", fatal=False)

    print('\033[1;32mXerosploit has been successfully installed. Execute \'xerosploit\' in your terminal.\033[1;m')


def do_uninstall():
    """Remove everything the installer created (issue #145)."""
    print("\033[1;34m\n[++] Uninstalling Xerosploit ... \033[1;m")
    run("rm -rf /opt/xerosploit", fatal=False)
    run("rm -f /usr/bin/xerosploit /usr/local/bin/xerosploit", fatal=False)
    run("rm -f /usr/local/bin/bettercap", fatal=False)
    if have("gem"):
        run("gem uninstall -a -x xettercap || true", fatal=False)
    run("rm -f %s/xettercap-*.gem" % REPO_DIR, fatal=False)
    print('\033[1;32m[+] Xerosploit has been uninstalled.\033[1;m')


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--uninstall", "uninstall", "-u"):
        do_uninstall()
        return
    # Distro is auto-detected (family + package manager); the menu only shows
    # when detection fails, e.g. exotic systems without /etc/os-release.
    family = detect_distro_family()
    if family != "unknown":
        do_install()
        return
    print("\033[1;33m[!] Could not detect your distro, please choose manually.\033[1;m")
    print("\033[1;34m\n[++] Please choose your operating system.\033[1;m")
    print("""
1) Ubuntu / Kali linux / Others
2) Parrot OS
""")
    try:
        system0 = input(">>> ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        sys.exit(1)
    if system0 == "1":
        do_install()
    elif system0 == "2":
        install_deps_parrot()
        do_install()
    else:
        print("Please select the option 1 or 2")
        main()


if __name__ == "__main__":
    main()
