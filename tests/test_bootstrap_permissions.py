"""Run as root on a disposable POSIX host to exercise real daemon credentials."""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("bootstrap_permissions", str(REPO / "scripts/nexus-bootstrap"))
spec = importlib.util.spec_from_loader(loader.name, loader)
bootstrap = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bootstrap
loader.exec_module(bootstrap)


@unittest.skipUnless(os.geteuid() == 0, "requires root to drop to daemon credentials")
class TrustConfigPermissions(unittest.TestCase):
    def as_daemon(self, operation):
        account = pwd.getpwnam("daemon")
        child = os.fork()
        if child == 0:
            try:
                os.setgroups([account.pw_gid])
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
                operation()
            except BaseException as error:
                print(error, file=sys.stderr, flush=True)
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_daemon_cannot_rewrite_replace_or_unlink_anchors_but_can_onboard_in_data(self):
        account = pwd.getpwnam("daemon")
        with tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()), prefix="nexus-permissions-") as temporary:
            parent = Path(temporary)
            os.chown(parent, 0, account.pw_gid)
            parent.chmod(0o750)
            state = parent / "state"
            state.mkdir()
            os.chown(state, account.pw_uid, account.pw_gid)
            target = state / "lemonade-nexus.json"
            target.write_text('{"root_pubkey":"original"}')
            os.chown(target, account.pw_uid, account.pw_gid)
            self.as_daemon(lambda: target.write_text('{"root_pubkey":"compromised"}'))
            with target.open("w") as stale_descriptor:
                bootstrap.trusted_directory(state, account.pw_gid)
                config = bootstrap.BootstrapConfig(str(state / "data"), root_pubkey="operator-root",
                                                   genesis_pubkey="operator-genesis",
                                                   release_signing_pubkey="operator-release")
                bootstrap.write_config(target, config, account.pw_gid)
                stale_descriptor.write("stale descriptor attack")
                stale_descriptor.flush()
                self.assertEqual(json.loads(target.read_text())["root_pubkey"], "operator-root")
            data = state / "data"
            data.mkdir(mode=0o700)
            os.chown(data, account.pw_uid, account.pw_gid)
            def runtime():
                self.assertEqual(json.loads(target.read_text())["root_pubkey"], "operator-root")
                staging = data / "onboarding.json"
                staging.write_text(target.read_text())
                for action in [lambda: target.write_text("attack"), lambda: target.unlink(),
                               lambda: os.replace(staging, target)]:
                    with self.assertRaises(PermissionError):
                        action()
                self.assertTrue(staging.exists())
            self.as_daemon(runtime)
            self.assertEqual(target.stat().st_uid, 0)
            self.assertEqual(state.stat().st_uid, 0)

    def test_symlink_and_daemon_owned_ancestor_are_rejected(self):
        account = pwd.getpwnam("daemon")
        with tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()), prefix="nexus-permissions-") as temporary:
            parent = Path(temporary)
            real = parent / "real"
            real.mkdir()
            link = parent / "link"
            link.symlink_to(real)
            with self.assertRaises(ValueError):
                bootstrap.trusted_directory(link, account.pw_gid)
            os.chown(parent, account.pw_uid, account.pw_gid)
            with self.assertRaises(ValueError):
                bootstrap.trusted_directory(real, account.pw_gid)


if __name__ == "__main__":
    unittest.main()
