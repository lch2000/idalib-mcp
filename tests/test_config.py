from __future__ import annotations

import json
import os
import platform
import tempfile
import unittest
from pathlib import Path

from idalib_mcp.config import (
    configure_idalib_environment,
    ida_library_name,
    idapro_config_path,
    validate_ida_home,
)


class ConfigTests(unittest.TestCase):
    def make_fake_ida_home(self, root: Path) -> Path:
        ida_home = root / "ida"
        ida_home.mkdir()
        (ida_home / "ida.hlp").write_text("", encoding="utf-8")
        (ida_home / ida_library_name()).write_text("", encoding="utf-8")
        return ida_home

    def test_validate_ida_home_accepts_expected_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ida_home = self.make_fake_ida_home(Path(temp_dir))
            self.assertEqual(validate_ida_home(ida_home), ida_home.resolve())

    def test_configure_idalib_environment_writes_process_local_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ida_home = self.make_fake_ida_home(root)
            config_root = root / "config"
            env = {"PATH": "existing"}

            result = configure_idalib_environment(
                ida_home,
                env=env,
                config_root=config_root,
                cleanup_temp=False,
            )

            self.assertEqual(result, config_root.resolve())
            config_path = idapro_config_path(config_root)
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["Paths"]["ida-install-dir"], str(ida_home.resolve()))
            self.assertEqual(env["IDADIR"], str(ida_home.resolve()))
            self.assertEqual(env["IDA_HOME"], str(ida_home.resolve()))
            if platform.system() == "Windows":
                self.assertEqual(env["APPDATA"], str(config_root.resolve()))
                self.assertTrue(env["PATH"].startswith(str(ida_home.resolve()) + os.pathsep))
            else:
                self.assertEqual(env["HOME"], str(config_root.resolve()))


if __name__ == "__main__":
    unittest.main()
