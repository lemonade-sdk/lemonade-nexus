import argparse
import base64
from contextlib import redirect_stderr
import importlib.machinery
import importlib.util
import io
import json
import re
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("nexus_bootstrap", str(REPO / "scripts/nexus-bootstrap"))
spec = importlib.util.spec_from_loader(loader.name, loader)
bootstrap = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bootstrap
loader.exec_module(bootstrap)
BINARY = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None
KEY = "a" * 64
GOSSIP = base64.b64encode(bytes(range(32))).decode()


class BootstrapTest(unittest.TestCase):
    def test_rejects_invalid_inputs_before_side_effects(self):
        for option, values in {
            "--dns-port": ["0", "53", "65536", "-1", "5335,", "1e3", "1;touch /tmp/oops"],
            "--public-dns-port": ["0", "65536", "2.5"],
            "--log-level": ["verbose", 'debug", "root_pubkey": "bad'],
            "--acme-provider": ["invalid"],
            "--public-ip": ["example.com", "999.1.2.3", "fe80::1%eth0"],
            "--region": ["bad/name", 'us-east"', "\nregion"],
            "--wan-interface": ['eth0"; flush ruleset', "lo", "a" * 16],
        }.items():
            for value in values:
                with self.subTest(option=option, value=value), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        bootstrap.parse_args(["--test-release-key", option, value])

    def test_validates_key_forms(self):
        for key in [KEY, GOSSIP]:
            self.assertEqual(bootstrap.public_key(key), key)
        for key in ["g" * 64, "a" * 63, GOSSIP[:-1], "AAAA", GOSSIP + "\n"]:
            with self.subTest(key=key), self.assertRaises(argparse.ArgumentTypeError):
                bootstrap.public_key(key)

    def test_structured_json_roundtrip_and_root_only_write_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "lemonade-nexus.json"
            config = bootstrap.BootstrapConfig('data/quote" slash\\ newline\n $(touch never)',
                                               root_pubkey=KEY, genesis_pubkey=GOSSIP,
                                               release_signing_pubkey=KEY)
            with patch.object(os, "fchown") as chown:
                bootstrap.write_config(target, config, 2345)
            self.assertEqual(json.loads(target.read_text()), bootstrap.asdict(config))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            chown.assert_called_once()
            self.assertEqual(chown.call_args.args[1:], (0, 2345))
            self.assertEqual(list(target.parent.glob(".lemonade-nexus.json.*")), [])

    def test_native_first_run_uses_argument_vector_and_validates_config(self):
        self.assertIsNotNone(BINARY)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "quote' and \" dollars$(false)"
            state.mkdir()
            data = state / "data"
            data.mkdir()
            config = bootstrap.BootstrapConfig(str(data), region="us-east")
            target = state / "lemonade-nexus.json"
            with patch.object(os, "fchown"):
                bootstrap.write_config(target, config, 0)
            command = [str(BINARY), "--config", str(target), "--data-root", str(data), "--first-run"]
            env = {key: value for key, value in os.environ.items() if not key.startswith("SP_")}
            result = bootstrap.run(command, capture_output=True, cwd=state, env=env)
            self.assertIn("Identity pubkey:", result.stdout)
            again = bootstrap.run(command, capture_output=True, cwd=state, env=env)
            self.assertIn("(existing)", again.stdout)
            for field, value in [("dns_port", 9100), ("region", "invalid/region")]:
                with self.subTest(field=field):
                    bad = bootstrap.asdict(config)
                    bad[field] = value
                    target.write_text(json.dumps(bad))
                    with self.assertRaises(subprocess.CalledProcessError):
                        bootstrap.run(command, capture_output=True, cwd=state, env=env)

    def test_bootstrap_preserves_anchors_and_invokes_server_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            account = type("Account", (), {"pw_uid": 1234, "pw_gid": 2345})()
            def directory_setup(path, gid):
                path.mkdir(mode=0o750)
            def first_run(command, **kwargs):
                self.assertEqual(command[:4], ["runuser", "-u", "lemonade-nexus", "--"])
                self.assertNotIn("shell", kwargs)
                self.assertNotIn("SP_ROOT_PUBKEY", kwargs["env"])
                self.assertNotIn("sh", command)
                return subprocess.CompletedProcess(command, 0, f"Identity pubkey:  {KEY}\nGossip pubkey:    {GOSSIP}\n")
            with patch.dict(os.environ, {"NEXUS_STATE_DIR": str(state), "NEXUS_USER": "lemonade-nexus", "SP_ROOT_PUBKEY": "evil"}), \
                 patch.object(os, "geteuid", return_value=0), \
                 patch.object(bootstrap.pwd, "getpwnam", return_value=account), \
                 patch.object(bootstrap, "trusted_directory", side_effect=directory_setup), \
                 patch.object(os, "chown"), patch.object(os, "fchown"), \
                 patch.object(bootstrap, "run", side_effect=first_run):
                bootstrap.bootstrap(bootstrap.parse_args(["--release-signing-pubkey", KEY]))
            config = json.loads((state / "lemonade-nexus.json").read_text())
            self.assertEqual(config["root_pubkey"], KEY)
            self.assertEqual(config["genesis_pubkey"], GOSSIP)
            self.assertEqual(config["release_signing_pubkey"], KEY)
            self.assertEqual(stat.S_IMODE((state / "data").stat().st_mode), 0o700)

    def test_nat_preserves_config_directory_group_and_checks_before_enabling(self):
        args = bootstrap.parse_args(["--test-release-key", "--install-dns-nat", "--wan-interface", "eth0"])
        for reject in [False, True]:
            with self.subTest(reject=reject), tempfile.TemporaryDirectory() as directory:
                conf = Path(directory) / "nexus-dns-nat.conf"
                conf.write_text("previous configuration")
                def paths(value):
                    return conf if value == "/etc/lemonade-nexus/nexus-dns-nat.conf" else Path(value)
                calls = []
                def command(arguments, **kwargs):
                    calls.append(arguments)
                    if reject and arguments[:2] == ["nft", "-c"]:
                        raise subprocess.CalledProcessError(1, arguments)
                    return subprocess.CompletedProcess(arguments, 0)
                with patch.object(bootstrap, "Path", side_effect=paths), \
                     patch.object(bootstrap, "trusted_directory") as protected, \
                     patch.object(bootstrap, "run", side_effect=command):
                    if reject:
                        with self.assertRaises(subprocess.CalledProcessError):
                            bootstrap.dns_nat(args, 2345)
                    else:
                        bootstrap.dns_nat(args, 2345)
                protected.assert_called_once_with(conf.parent, 2345)
                if reject:
                    self.assertEqual(conf.read_text(), "previous configuration")
                    self.assertFalse(any(call[0] == "systemctl" for call in calls))
                else:
                    self.assertIn('define nexus_wan_if = "eth0"', conf.read_text())
                    self.assertIn("define nexus_dns_port = 5335", conf.read_text())
                    self.assertEqual(calls[1][:2], ["nft", "-c"])
                    self.assertEqual(calls[-1], ["systemctl", "enable", "--now", "nexus-dns-nat.service"])

    def test_shipped_units_only_reference_units_that_exist_or_are_system_wide(self):
        shipped = set()
        unit_directories = [REPO / "packaging/systemd",
                            REPO / "projects/LemonadeNexusAttestd/systemd"]
        for directory in unit_directories:
            shipped.update(path.name for path in directory.glob("*.service"))
        self.assertTrue(shipped)
        allowlist = {
            "network-online.target",
            "network-pre.target",
            "local-fs.target",
            "multi-user.target",
            "nftables.service",
        }
        for directory in unit_directories:
            for unit in sorted(directory.glob("*.service")):
                for line in unit.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    key, sep, value = line.partition("=")
                    if not sep or key not in ("Wants", "Requires", "After", "BindsTo"):
                        continue
                    for name in value.split():
                        self.assertIn(name, shipped | allowlist,
                                      f"{unit.name} references {name} but it is "
                                      f"neither shipped by this tree nor a system unit")

    def test_packaging_protects_config_and_allows_runtime_data_only(self):
        unit = (REPO / "packaging/systemd/lemonade-nexus.service").read_text()
        self.assertIn("ReadWritePaths=/var/lib/lemonade-nexus/data\n", unit)
        self.assertIn("ReadOnlyPaths=/etc/lemonade-nexus /var/lib/lemonade-nexus\n", unit)
        self.assertIn("ExecStart=/usr/bin/lemonade-nexus\n", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        postinst = (REPO / "packaging/debian/postinst").read_text()
        self.assertIn("install -d -o root -g lemonade-nexus -m 0750 /var/lib/lemonade-nexus\n", postinst)
        self.assertIn("install -o root -g lemonade-nexus -m 0640 /var/lib/lemonade-nexus/lemonade-nexus.json", postinst)
        self.assertNotIn("SP_JWT_SECRET=", postinst)
        self.assertNotIn("enable --now lemonade-nexus", postinst)
        self.assertNotIn("start lemonade-nexus.service", postinst)
        nat = (REPO / "packaging/nftables/nexus-dns-nat.nft").read_text()
        for transport in ("udp", "tcp"):
            self.assertIn(f"iifname $nexus_wan_if {transport} dport $nexus_public_dns_port redirect to :$nexus_dns_port", nat)

    def test_postinst_creates_attestd_user_groups_and_enables_unit(self):
        postinst = (REPO / "packaging/debian/postinst").read_text()
        # (a) the unit's User=/Group= must resolve: a dedicated system account,
        # created only when absent, mirroring the lemonade-nexus user.
        self.assertIn("id -u nexus-attestd", postinst)
        self.assertIn("groupadd --system nexus-attestd", postinst)
        self.assertIn("useradd --system --no-create-home --shell /usr/sbin/nologin", postinst)
        self.assertRegex(postinst,
                         r"useradd --system[^\n]*\\\n"
                         r"\s*--home-dir /nonexistent --gid nexus-attestd nexus-attestd")
        # (b) SupplementaryGroups=tss nexus: membership added for every group
        # that exists, each checked before usermod, idempotent like the
        # lemonade-nexus membership above.
        for group in ("tss", "nexus"):
            with self.subTest(group=group):
                self.assertRegex(postinst, rf'grep -qx {group}; then')
                self.assertIn(f'usermod -a -G {group} nexus-attestd', postinst)
        # (c) the unit is enabled, under the same guard as the server unit:
        # a plain systemctl enable, no --now and no start.
        self.assertIn("systemctl enable lemonade-nexus.service", postinst)
        self.assertIn("systemctl enable nexus-attestd.service", postinst)
        self.assertNotIn("enable --now nexus-attestd", postinst)
        self.assertNotIn("start nexus-attestd", postinst)

    def test_attestd_unit_masks_lemonade_nexus_data_root(self):
        unit = (REPO / "projects/LemonadeNexusAttestd/systemd/nexus-attestd.service").read_text()
        lines = [line for line in unit.splitlines() if line.startswith("InaccessiblePaths=")]
        self.assertTrue(lines)
        self.assertIn("-/var/lib/lemonade-nexus", " ".join(lines))
        self.assertNotIn("-/var/lib/nexus", " ".join(lines).replace("-/var/lib/lemonade-nexus", ""))


class WorkflowMatrixConsistencyTest(unittest.TestCase):
    # release.yml ships binaries for whatever it builds, so it must never be
    # active on a platform that ci.yml does not gate (the Windows entries in
    # both files are disabled together — see their TODO(windows) comments).

    @staticmethod
    def _active_matrix_platforms(workflow_path):
        # Collects the `platform:` value of every ACTIVE (uncommented) matrix
        # entry in the file: a list item under an `include:` key counts, and
        # the list ends at the first line (comment or not) indented at or
        # below the `include:` line. Commented-out entries are skipped.
        platforms = []
        include_indent = None
        for line in workflow_path.read_text().splitlines():
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()
            if include_indent is not None and indent <= include_indent:
                include_indent = None
            if stripped.startswith("include:"):
                include_indent = indent
            elif include_indent is not None and not stripped.startswith("#"):
                match = re.search(r"platform:\s*(\S+)", stripped)
                if match:
                    platforms.append(match.group(1))
        return platforms

    def test_release_does_not_ship_platforms_ci_does_not_gate(self):
        ci_platforms = self._active_matrix_platforms(REPO / ".github/workflows/ci.yml")
        release_platforms = self._active_matrix_platforms(REPO / ".github/workflows/release.yml")
        self.assertIn("linux-x86_64", ci_platforms)
        self.assertIn("darwin-arm64", ci_platforms)
        for platform in release_platforms:
            with self.subTest(platform=platform):
                self.assertIn(platform, ci_platforms,
                              f"release.yml ships {platform} but ci.yml does not gate it")
        # Windows is currently disabled in both files; a re-enable must be done
        # in both together (see the TODO(windows) comments in each workflow).
        self.assertEqual([p for p in release_platforms if p.startswith("windows-")], [])
        self.assertEqual([p for p in ci_platforms if p.startswith("windows-")], [])


if __name__ == "__main__":
    unittest.main()
