#!/bin/sh

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

# Xerosploit launcher (installed as /usr/bin/xerosploit).
# Fixes 'xerosploit: command not found' (issues #348/#351) and
# 'python: not found' on modern distros where only python3 exists.
# The interpreter is auto-detected (python3.x >= 3.8, Arch's `python`,
# versioned binaries...), instead of assuming `python3` exists.
# Prefer the installed copy, fall back to a repo checkout layout.

# UTF-8 locale: Docker/minimal images default to POSIX, which made Python
# crash with UnicodeEncodeError on the box-drawing tables (issue #271).
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"

find_python() {
    # Echo the first candidate that runs and is Python >= 3.8.
    for _c in python3 python3.15 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python; do
        if command -v "$_c" >/dev/null 2>&1; then
            if "$_c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
                echo "$_c"
                return 0
            fi
        fi
    done
    return 1
}

PY="$(find_python)" || {
    echo "[!] No usable Python 3 (>= 3.8) found. Install it with your package manager, e.g.:" >&2
    echo "    Debian/Ubuntu/Kali/Parrot: sudo apt-get install -y python3" >&2
    echo "    Fedora/RHEL:              sudo dnf install -y python3" >&2
    echo "    Arch/Manjaro/BlackArch:   sudo pacman -S --needed python" >&2
    exit 1
}

if [ -f /opt/xerosploit/xerosploit.py ]; then
    exec "$PY" /opt/xerosploit/xerosploit.py "$@"
else
    # Running from a git clone without installing: resolve relative to this script.
    # (Portable: no `readlink -f`, which macOS lacks - issue #342.)
    HERE=$(dirname "$0")
    case "$HERE" in
        /*) ;;
        *) HERE="$(pwd)/$HERE" ;;
    esac
    if [ -f "$HERE/xerosploit.py" ]; then
        exec "$PY" "$HERE/xerosploit.py" "$@"
    else
        echo "[!] xerosploit.py not found. Run: sudo $PY install.py" >&2
        exit 1
    fi
fi


