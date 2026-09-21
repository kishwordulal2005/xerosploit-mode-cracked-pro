
[![Version](https://img.shields.io/badge/Xerosploit-Version_1.0-brightgreen.svg?maxAge=259200)]()
[![PyPI](https://img.shields.io/badge/Python-3-blue.svg)]()
[![Build](https://img.shields.io/badge/Supported_OS-linux-orange.svg)]()
[![AUR](https://img.shields.io/aur/license/yaourt.svg)]()

Xerosploit
=
Xerosploit is a penetration testing toolkit whose goal is to perform man in the middle attacks for testing purposes. It brings various modules that allow to realise efficient attacks, and also allows to carry out denial of service attacks and port scanning.
Powered by <a href="https://www.bettercap.org"> bettercap</a> and <a href="https://www.bettercap.org"> nmap</a>.

![](http://i.imgur.com/bbr48Ep.png)

Dependencies
=

- nmap
- hping3
- build-essential (or distro equivalent)
- libpcap-dev / libpcap-devel / libpcap (bettercap links libpcap at runtime)
- libgmp-dev
- python3-tabulate
- terminaltables (via pip — no apt package exists in Debian/Kali)
- python3-pil
- driftnet (optional, for driftnet module)
- xterm (optional, for sniff log window)

bettercap v2 (currently v2.41.7, see `tools/bettercap2/BETTERCAP_VERSION`)
is fetched automatically: prebuilt static binary on amd64, compiled from
source on ARM/Raspberry Pi (needs `golang` + pcap/usb/netfilter headers,
installed automatically). No Ruby, no gems.




Installation
=
Dependencies will be automatically installed.

    git clone https://github.com/LionSec/xerosploit
    cd xerosploit && sudo python3 install.py
    sudo xerosploit

The installer auto-detects your distro (Kali/Debian/Ubuntu/Parrot/Fedora/
Arch/...), its package manager (apt/dnf/pacman), and a usable Python 3
(>= 3.8) — downloading Python automatically if missing. Works on VM or
bare metal. No menu choices needed on supported systems.

To uninstall: `sudo python3 install.py --uninstall` (issue #145).

> Note: Python 2 / `python-pip` / `libgmp3-dev` no longer exist on modern
> Kali/Ubuntu. Use `python3` and `pip3 install --break-system-packages`
> (handled automatically by `install.py`). Most MITM modules only work on
> plain HTTP — HTTPS/HSTS sites cannot be stripped on modern browsers.

Troubleshooting (answers to the most reported issues)
=

- `xerosploit: command not found`: re-run the installer
  (`sudo python3 install.py`) so `/usr/bin/xerosploit` is installed.
- `bettercap: command not found`: re-run the installer; on amd64 it
  downloads the official binary, on ARM it compiles from source (takes a
  few minutes, needs network + golang toolchain).
- Legacy `xettercap` / Ruby gem errors (`original_argv`, `File.exists?`,
  `SortedSet`, `pcap.h`, EventMachine): those belonged to the retired
  bettercap 1.x fork. Re-run the current installer, which removes the old
  gem and installs bettercap v2 instead.
- `route: not found`, gateway shows `via`: fixed by auto-detection via
  `ip route`; if it persists, set values manually with the `iface` and
  `gateway` commands (use `0` for auto).
- Interface names with `-` or `.` (e.g. `br-xe`, `eth0.100`): bettercap v2's
  ARP table parser only matches plain names like `eth0`/`wlan0`, so spoofing
  silently finds no targets. Rename the interface or use an alias without
  dashes/dots if possible.
- After a crash/`kill -9`, stale iptables NAT rules may linger: flush them
  with `sudo iptables -t nat -F` (normal Ctrl+C stops clean up by itself).
- `UnicodeEncodeError` in Docker/SSH: fixed by forcing a UTF-8 locale;
  also export `LANG=C.UTF-8 LC_ALL=C.UTF-8` in minimal images.
- Scan finds nothing / only your own host: in a VM use **Bridged**
  networking (NAT isolates the VM). On WSL1, scanning/MITM is unreliable;
  use a VM or native install.
- Inject/deface/replace/yplay "do nothing" or stop at once: these only work
  on plain **HTTP** pages. HTTPS/HSTS sites (YouTube, Google, Facebook…)
  cannot be modified — that is expected, not a bug.
- Only one module at a time: run a single module per target (e.g. sniff
  *or* dspoof, not both together).
- Target loses internet during MITM: IP forwarding must be on
  (`echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward`); NAT-mode VMs also
  cause this — prefer Bridged mode.
- `driftnet` fails: install it (`sudo apt-get install -y driftnet`); it
  only sees unencrypted traffic.
- Only `ping`/`pscan` work but every MITM module fails: those two don't use
  bettercap — check that `bettercap` runs (`bettercap -h`) and re-run the
  installer if it doesn't.
- SSL interception: answer `y` at the sniff sslstrip prompt (enables the
  HTTP + HTTPS proxies) AND install xerosploit's CA into the victim's
  browser/OS store (lab: `curl --cacert ca.crt`). The CA lives at
  `tools/bettercap2/ca.crt` (installed copy: `/opt/xerosploit/...`), is
  valid 10 years (2026–2036), auto-renews before expiry, and its SHA256
  fingerprint prints at setup — verify it on the victim. Without a trusted
  CA, HTTPS fails closed on the victim — correct TLS behavior, not a bug.
  Downgrade-only tricks (link rewriting, HSTS stripping) still apply solely
  to pages first visited over plain HTTP. HSTS-preloaded/pinned targets
  additionally refuse any downgrade; test those only with a trusted CA.
- Phone hotspot targets show nothing: hotspots use client isolation, which
  blocks MITM between clients. Test on a normal router/WLAN instead.
- Docker: run privileged with host networking
  (`docker run --privileged --net=host ...`) and set `iface`/`gateway`
  manually if auto-detect fails.
- ARM/Raspberry Pi: supported via source build (installer compiles bettercap
  with the Go toolchain — takes a few minutes, needs network). amd64 uses a
  prebuilt, sha256-verified binary.
- Native Windows is unsupported (`os.geteuid`); use Kali in a VM.
  macOS/Termux are not officially supported.


Tested on
=

<table>
    <tr>
        <th>Operative system</th>
        <th> Version </th>
    </tr>
    <tr>
        <td>Ubuntu</td>
        <td> 16.04  / 15.10 </td>
    </tr>
    <tr>
        <td>Kali linux</td>
        <td> Rolling / Sana</td>
    </tr>
    <tr>
        <td>Parrot OS</td>
        <td>3.1 </td>
    </tr>
</table>



features 
=
- Port scanning
- Network mapping
- Dos attack
- Html code injection
- Javascript code injection
- Download intercaption and replacement
- Sniffing
- Dns spoofing
- Background audio reproduction
- Images replacement
- Drifnet
- Webpage defacement and more ...

Demonstration
=
https://www.youtube.com/watch?v=35QUrtZEV9U

I have some questions!
=

Please visit https://github.com/LionSec/xerosploit/issues

Donations
=
- Paypal : https://www.paypal.me/lionsec
- Bitcoin : 12dM5kZjYMizNuXaqu7QZBLNDkXjfKYpRD


Contact
=
- Website : https://neodrix.com
- Youtube : https://youtube.com/inf98es
- Facebook : https://facebook.com/in98
- Twitter: @LionSec1
- Email : informatic98es@gmail.com
