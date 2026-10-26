"""Checks of scripts/nexus-tree-migrate that need no running server."""

import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import tempfile
import threading
import unittest

REPO = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("nexus_tree_migrate",
                                              str(REPO / "scripts/nexus-tree-migrate"))
spec = importlib.util.spec_from_loader(loader.name, loader)
migrate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = migrate
loader.exec_module(migrate)


def add_file(tar, name, text=b"{}"):
    info = tarfile.TarInfo(name)
    info.size = len(text)
    tar.addfile(info, io.BytesIO(text))


class TreeMigrateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_extracts_a_backup_and_finds_its_data_directory(self):
        archive = self.dir / "state.tar"
        with tarfile.open(archive, "w") as tar:
            add_file(tar, "var/lib/lemonade-nexus/data/tree/nodes/root.json")
            add_file(tar, "var/lib/lemonade-nexus/data/ipam/allocations.json")
            link = tarfile.TarInfo("var/lib/lemonade-nexus/data/tree/nodes/link.json")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/shadow"
            tar.addfile(link)
        out = self.dir / "out"
        out.mkdir()
        migrate.safe_extract(archive, out)
        data = migrate.find_data_root(out)
        self.assertEqual(data.resolve(), (out / "var/lib/lemonade-nexus/data").resolve())
        self.assertTrue((data / "tree/nodes/root.json").is_file())
        self.assertFalse((data / "tree/nodes/link.json").exists())  # links are skipped

    def test_refuses_a_backup_path_that_leaves_the_extraction_directory(self):
        archive = self.dir / "evil.tar"
        with tarfile.open(archive, "w") as tar:
            add_file(tar, "../escaped.json")
        out = self.dir / "out"
        out.mkdir()
        with self.assertRaises(SystemExit):
            migrate.safe_extract(archive, out)
        self.assertFalse((self.dir / "escaped.json").exists())

    def test_two_data_directories_are_refused(self):
        for name in ("a", "b"):
            (self.dir / name / "tree" / "nodes").mkdir(parents=True)
        with self.assertRaises(SystemExit):
            migrate.find_data_root(self.dir)

    def test_member_urls_come_from_the_context_or_an_override(self):
        ctx = {"members": [
            {"signer": "ed25519:A", "address": "10.10.12.50:9102", "http_port": 9100},
            {"signer": "ed25519:B", "address": "", "http_port": 0},
        ]}
        urls = migrate.member_urls(ctx, {"ed25519:B": "https://sn02.example.test:9100/"})
        self.assertEqual(urls["ed25519:A"], "https://10.10.12.50:9100")
        self.assertEqual(urls["ed25519:B"], "https://sn02.example.test:9100")
        with self.assertRaises(SystemExit):
            migrate.member_urls(ctx, {})

    def test_an_address_url_keeps_the_chain_check_but_not_the_name_check(self):
        by_ip = migrate.tls_context("https://10.10.12.50:9100", insecure=False)
        self.assertFalse(by_ip.check_hostname)
        self.assertNotEqual(by_ip.verify_mode, 0)
        by_name = migrate.tls_context("https://sn01.example.test:9100", insecure=False)
        self.assertTrue(by_name.check_hostname)

    def test_the_control_socket_carries_one_line_each_way(self):
        # A short path: Unix socket names are limited to about 100 bytes.
        short = tempfile.mkdtemp(prefix="ntm", dir="/tmp")
        self.addCleanup(lambda: os.path.isdir(short) and __import__("shutil").rmtree(short))
        path = os.path.join(short, "c.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        seen = {}

        def serve():
            conn, _ = server.accept()
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    data += conn.recv(4096)
                seen.update(json.loads(data))
                conn.sendall(b'{"ok":true,"echo":"' + seen["op"].encode() + b'"}\n')

        thread = threading.Thread(target=serve)
        thread.start()
        reply = migrate.control({"op": "tree_merge_context"}, path)
        thread.join()
        server.close()
        self.assertEqual(reply, {"ok": True, "echo": "tree_merge_context"})
        self.assertEqual(seen["op"], "tree_merge_context")

    def _collect(self, answers, backup=None):
        ctx = {"members": [{"signer": s, "address": f"10.0.0.{i}:9102", "http_port": 9100}
                           for i, s in enumerate(answers)]}
        args = type("Args", (), {"servers": {}, "socket": "unused", "insecure_tls": False,
                                 "backup": backup})()
        status_for = {f"https://10.0.0.{i}:9100": answers[s] for i, s in enumerate(answers)}
        old_control, old_post = migrate.control, migrate.post
        migrate.control = lambda request, path: {"ok": True, "body": {"request": "r"}}
        migrate.post = lambda url, body, insecure: status_for[url.rsplit("/api", 1)[0]]
        try:
            return migrate.collect(args, ctx, self.dir)
        finally:
            migrate.control, migrate.post = old_control, old_post

    def test_nothing_to_merge_when_no_member_awaits_a_merge(self):
        not_awaiting = (409, {"error": "this server is not awaiting the tree merge commit"})
        self.assertIsNone(self._collect({"ed25519:A": not_awaiting, "ed25519:B": not_awaiting}))

    def test_a_mix_of_awaiting_and_empty_members_is_refused(self):
        not_awaiting = (409, {"error": "this server is not awaiting the tree merge commit"})
        export = (200, {"signer": "ed25519:B", "server": "b", "nodes": []})
        with self.assertRaises(SystemExit):
            self._collect({"ed25519:A": not_awaiting, "ed25519:B": export})

    def test_members_that_await_give_their_exports_without_a_backup(self):
        exports = self._collect({"ed25519:A": (200, {"signer": "ed25519:A", "nodes": [1]})})
        self.assertEqual(exports, [{"signer": "ed25519:A", "nodes": [1]}])


if __name__ == "__main__":
    unittest.main()
