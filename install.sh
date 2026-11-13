#!/bin/sh
# Torwell installer / uninstaller (Linux x86_64).
#
#   curl -fsSL https://raw.githubusercontent.com/se7enbyte/torwell/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/se7enbyte/torwell/main/install.sh | sh -s -- --uninstall
#
# Installs the runtime dependencies (tor, nftables, polkit) with your package manager,
# downloads the release tarball, verifies its SHA-256 and installs:
#   /usr/bin/torwell-ui, /usr/bin/torwell-engine,
#   /usr/share/polkit-1/actions/org.torwell.engine.policy
# The binaries must be root-owned and not writable by others: the engine refuses to elevate
# through pkexec otherwise. It never starts or enables your distribution's tor.service.
# Environment: TORWELL_VERSION=0.1.0 pins a version (default: latest release).
set -eu

REPO=se7enbyte/torwell
POLICY=/usr/share/polkit-1/actions/org.torwell.engine.policy

say() { printf '%s\n' "$*"; }
die() { printf 'torwell install: %s\n' "$*" >&2; exit 1; }

usage() {
	say "usage: install.sh [--uninstall | --help]"
	say "  (no option)   install or upgrade torwell"
	say "  --uninstall   remove torwell (refuses while torwell is active)"
}

ACTION=install
case "${1:-}" in
	"") ;;
	--uninstall) ACTION=uninstall ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; exit 2 ;;
esac

[ "$(uname -s)" = Linux ] || die "only Linux is supported"
[ "$(uname -m)" = x86_64 ] || die "only x86_64 builds are published (found $(uname -m))"

if [ "$(id -u)" -eq 0 ]; then
	SUDO=
elif command -v sudo >/dev/null 2>&1; then
	SUDO=sudo
else
	die "run as root or install sudo"
fi

uninstall() {
	if [ -e /var/lib/torwell/state.json ]; then
		say "torwell is active or was not stopped cleanly (/var/lib/torwell/state.json exists)."
		say "Stop it first: torwell-ui -> Stop (or Recover). If that is impossible:"
		say "  sudo nft delete table inet torwell"
		say "  sudo systemctl stop torwell-tor.service"
		say "  sudo rm -r /var/lib/torwell"
		exit 1
	fi
	if [ -x /usr/bin/torwell-engine ]; then
		$SUDO /usr/bin/torwell-engine boot-protection disable >/dev/null 2>&1 || true
	fi
	$SUDO rm -f /usr/bin/torwell-ui /usr/bin/torwell-engine "$POLICY"
	say "torwell removed. tor, nftables and polkit were left installed."
}

install_deps() {
	if command -v pacman >/dev/null 2>&1; then
		$SUDO pacman -S --needed --noconfirm tor nftables polkit
	elif command -v apt-get >/dev/null 2>&1; then
		$SUDO apt-get update
		# Newer Debian/Ubuntu split polkit into polkitd + pkexec; older ones ship policykit-1.
		$SUDO apt-get install -y tor nftables polkitd pkexec ||
			$SUDO apt-get install -y tor nftables policykit-1
	elif command -v dnf >/dev/null 2>&1; then
		$SUDO dnf install -y tor nftables polkit
	elif command -v zypper >/dev/null 2>&1; then
		$SUDO zypper --non-interactive install tor nftables polkit
	else
		say "Unknown package manager: install tor, nftables and polkit (pkexec) yourself."
	fi
	for tool in tor nft pkexec; do
		command -v "$tool" >/dev/null 2>&1 || [ -x "/usr/bin/$tool" ] || [ -x "/usr/sbin/$tool" ] ||
			die "'$tool' is still missing"
	done
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

install_torwell() {
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
	install_deps

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	version=${TORWELL_VERSION:-}
	if [ -z "$version" ]; then
		fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp/latest.json"
		version=$(sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)
		[ -n "$version" ] || die "could not find the latest release of $REPO"
	fi
	name="torwell-$version-x86_64-linux"
	base="https://github.com/$REPO/releases/download/v$version"
	say "Downloading torwell $version ..."
	fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz"
	fetch "$base/$name.tar.gz.sha256" "$tmp/$name.tar.gz.sha256"
	(cd "$tmp" && sha256sum -c "$name.tar.gz.sha256") || die "checksum mismatch, nothing installed"
	tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

	src="$tmp/$name"
	$SUDO install -o root -g root -Dm755 "$src/bin/torwell-engine" /usr/bin/torwell-engine
	$SUDO install -o root -g root -Dm755 "$src/bin/torwell-ui" /usr/bin/torwell-ui
	$SUDO install -o root -g root -Dm644 "$src/share/polkit-1/actions/org.torwell.engine.policy" "$POLICY"

	say ""
	say "torwell $version installed. Run: torwell-ui"
	say "Reboot protection is off. To keep the block across reboots:"
	say "  sudo torwell-engine boot-protection enable"
	say "While torwell is active all LAN traffic is blocked too (VPN apps, Deskflow, printers...)."
}

if [ "$ACTION" = uninstall ]; then
	uninstall
else
	install_torwell
fi
