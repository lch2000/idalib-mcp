from __future__ import annotations

import unittest
from pathlib import Path

from idalib_mcp.worker import split_worker_args


class WorkerArgTests(unittest.TestCase):
    def test_split_worker_args_removes_local_ida_options(self) -> None:
        ida_home, config_root, remaining = split_worker_args(
            [
                "--ida-home",
                "D:/IDA",
                "--ida-config-root",
                "D:/tmp/config",
                "--host",
                "127.0.0.1",
                "--port",
                "9000",
            ]
        )

        self.assertEqual(ida_home, Path("D:/IDA"))
        self.assertEqual(config_root, Path("D:/tmp/config"))
        self.assertEqual(remaining, ["--host", "127.0.0.1", "--port", "9000"])


if __name__ == "__main__":
    unittest.main()
