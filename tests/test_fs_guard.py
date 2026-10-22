"""Unit tests for tools/fs_guard.py (Workspace security, path validation, limits)."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.paths import PROJECT_ROOT
from tools.fs_guard import (
    PathValidationError,
    WorkspaceSecurityError,
    WriteSizeLimitError,
    check_write_size,
    resolve_workspace,
    truncate_result,
    validate_path,
)


class TestFSGuard(unittest.TestCase):
    """Test suite for fs_guard security and limit functions."""

    def setUp(self):
        # Create an isolated temporary directory outside the project root for testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(os.path.realpath(self.temp_dir.name))
        self.ws_dir = self.temp_path / "assistant_test_ws"
        self.ws_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        # Safely remove any junction if created before cleanup
        junction_path = self.ws_dir / "junction_outside"
        if os.path.exists(junction_path):
            try:
                os.rmdir(junction_path)
            except Exception:
                pass
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # 3a) workspace project root ke andar / barabar / parent -> exception
    def test_workspace_project_root_security(self):
        # Workspace equals project root
        with self.assertRaises(WorkspaceSecurityError) as ctx:
            resolve_workspace(PROJECT_ROOT)
        self.assertIn("cannot be the same as project root", str(ctx.exception))

        # Workspace inside project root
        inside_ws = PROJECT_ROOT / "sub_workspace_test"
        with self.assertRaises(WorkspaceSecurityError) as ctx:
            resolve_workspace(inside_ws)
        self.assertIn("cannot be inside project root", str(ctx.exception))

        # Workspace is parent of project root
        parent_ws = PROJECT_ROOT.parent
        with self.assertRaises(WorkspaceSecurityError) as ctx:
            resolve_workspace(parent_ws)
        self.assertIn("cannot be a parent of project root", str(ctx.exception))

        # Workspace is root drive containing project root (e.g. C:\)
        drive_ws = Path(PROJECT_ROOT.anchor)
        with self.assertRaises(WorkspaceSecurityError) as ctx:
            resolve_workspace(drive_ws)
        self.assertIn("cannot be a parent of project root", str(ctx.exception))

    # 3b) workspace ke andar ki normal file -> allow
    def test_normal_file_inside_workspace_allowed(self):
        # Relative file
        res = validate_path("sample.txt", workspace=self.ws_dir)
        expected = Path(os.path.realpath(self.ws_dir / "sample.txt"))
        self.assertEqual(res, expected)

        # Subdirectory file
        res_sub = validate_path("docs/notes.md", workspace=self.ws_dir)
        expected_sub = Path(os.path.realpath(self.ws_dir / "docs/notes.md"))
        self.assertEqual(res_sub, expected_sub)

        # Absolute file inside workspace
        abs_file = self.ws_dir / "data.json"
        res_abs = validate_path(abs_file, workspace=self.ws_dir)
        self.assertEqual(res_abs, Path(os.path.realpath(abs_file)))

    # 3c) "..\\..\\.env" jaisa traversal -> deny
    def test_traversal_denied(self):
        with self.assertRaises(PathValidationError):
            validate_path(r"..\..\.env", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path("../../.env", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(r"sub\..\..\..\outside.txt", workspace=self.ws_dir)

    # 3d) C:\Windows\win.ini -> deny
    def test_absolute_outside_workspace_denied(self):
        with self.assertRaises(PathValidationError):
            validate_path(r"C:\Windows\win.ini", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(r"C:\Windows", workspace=self.ws_dir)

    # 3e) workspace ke andar junction jo bahar ke folder ki taraf jaye -> deny
    def test_junction_outside_denied(self):
        outside_dir = self.temp_path / "outside_dir"
        outside_dir.mkdir(parents=True, exist_ok=True)
        junction_path = self.ws_dir / "junction_outside"

        if os.name == "nt":
            cmd = f'cmd /c mklink /J "{junction_path}" "{outside_dir}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest(
                    f"Skipping junction test: OS refused mklink /J ({proc.stderr.strip() or proc.stdout.strip()})"
                )
        else:
            try:
                os.symlink(outside_dir, junction_path, target_is_directory=True)
            except OSError as e:
                self.skipTest(f"Skipping junction test: symlink creation failed: {e}")

        # Attempting to access junction itself or file within it
        with self.assertRaises(PathValidationError):
            validate_path(junction_path, workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(junction_path / "target.txt", workspace=self.ws_dir)

    # 3f) UNC path aur "file.txt:stream" -> deny
    def test_unc_and_stream_denied(self):
        # UNC paths
        with self.assertRaises(PathValidationError):
            validate_path(r"\\server\share\file.txt", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path("//server/share/file.txt", workspace=self.ws_dir)

        # NTFS Alternate Data Stream
        with self.assertRaises(PathValidationError):
            validate_path("file.txt:stream", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(r"sub\file.txt:stream", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(str(self.ws_dir / "file.txt:stream"), workspace=self.ws_dir)

    # 3g) case badal ke workspace path -> allow; protected naam ka case-variant (".ENV") -> deny
    def test_case_variation_and_protected_name(self):
        # Case changed workspace path inside workspace -> allow
        upper_path = str(self.ws_dir).upper() + "\\A.TXT"
        res = validate_path(upper_path, workspace=self.ws_dir)
        self.assertEqual(str(res).lower(), (str(self.ws_dir) + "\\a.txt").lower())

        # Protected name case-variant (.ENV, .Env, .GIT) -> deny
        with self.assertRaises(PathValidationError):
            validate_path(".ENV", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(".Env", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(r"..\..\.ENV", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(str(PROJECT_ROOT / ".ENV"), workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(".git", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path(".GIT", workspace=self.ws_dir)

    # 3h) truncate_result(25000 chars) -> 20000 + marker; check_write_size(1_000_001 bytes) -> exception
    def test_limits_truncate_and_write_size(self):
        # truncate_result with 25,000 characters
        long_text = "a" * 25000
        truncated = truncate_result(long_text, limit=20000)
        self.assertEqual(len(truncated), 20000 + len("[truncated]"))
        self.assertTrue(truncated.startswith("a" * 20000))
        self.assertTrue(truncated.endswith("[truncated]"))

        # truncate_result within limit
        short_text = "hello world"
        self.assertEqual(truncate_result(short_text, limit=20000), short_text)

        # check_write_size exceeding 1,000,000 bytes
        over_bytes = b"x" * 1_000_001
        with self.assertRaises(WriteSizeLimitError):
            check_write_size(over_bytes, limit=1_000_000)

        over_str = "x" * 1_000_001
        with self.assertRaises(WriteSizeLimitError):
            check_write_size(over_str, limit=1_000_000)

        # check_write_size exactly at or below limit
        exact_bytes = b"x" * 1_000_000
        check_write_size(exact_bytes, limit=1_000_000)  # should not raise

        small_bytes = b"x" * 500
        check_write_size(small_bytes, limit=1_000_000)  # should not raise

    # --- NAYE TESTS (Tests a to i) ---

    # a) mixed separator UNC: "\\/server/share/x" -> deny
    def test_mixed_separator_unc_denied(self):
        with self.assertRaises(PathValidationError):
            validate_path(r"\/server/share/x", workspace=self.ws_dir)
        with self.assertRaises(PathValidationError):
            validate_path(r"/\server/share/x", workspace=self.ws_dir)

    # b) sibling folder C:\dev\assistant-workspace-evil\a.txt -> deny
    def test_sibling_folder_denied(self):
        sibling_evil = str(self.ws_dir) + "-evil\\a.txt"
        with self.assertRaises(PathValidationError):
            validate_path(sibling_evil, workspace=self.ws_dir)

    # c) reserved names (CON, NUL, PRN, AUX, COM1, LPT1, "con.txt", "nul.log") workspace ke andar bhi -> deny
    def test_reserved_device_names_denied(self):
        reserved_list = [
            "CON", "NUL", "PRN", "AUX", "COM1", "LPT1",
            "con.txt", "nul.log", "sub/aux.txt", "COM9.dat"
        ]
        for name in reserved_list:
            with self.subTest(name=name):
                with self.assertRaises(PathValidationError):
                    validate_path(name, workspace=self.ws_dir)

    # d) "a.txt." aur "a.txt " aur folder component "sub." -> deny
    def test_trailing_dot_or_space_denied(self):
        invalid_paths = ["a.txt.", "a.txt ", "sub./file.txt", "sub.", "folder /file.txt"]
        for path_str in invalid_paths:
            with self.subTest(path=path_str):
                with self.assertRaises(PathValidationError):
                    validate_path(path_str, workspace=self.ws_dir)

    # e) 8.3 short-name jaisa component ("ASSIST~1") -> deny
    def test_short_name_8_3_denied(self):
        short_names = ["ASSIST~1", "FOOBAR~2.TXT", "sub/TEST~1/a.txt", "file~9.log"]
        for sn in short_names:
            with self.subTest(short_name=sn):
                with self.assertRaises(PathValidationError):
                    validate_path(sn, workspace=self.ws_dir)

    # f) "\\\\?\\C:\\dev\\assistant\\.env" aur "\\\\.\\COM1" -> deny
    def test_device_and_verbatim_paths_denied(self):
        paths = [
            r"\\?\C:\dev\assistant\.env",
            r"\\.\COM1",
            r"//?/C:/dev/assistant/.env",
            r"//./COM1",
        ]
        for p in paths:
            with self.subTest(path=p):
                with self.assertRaises(PathValidationError):
                    validate_path(p, workspace=self.ws_dir)

    # g) ".env.local", ".env.production", ".ENV" -> deny
    def test_env_prefix_and_git_denied(self):
        env_variants = [".env.local", ".env.production", ".ENV", ".env.test", ".env", ".git"]
        for ev in env_variants:
            with self.subTest(target=ev):
                with self.assertRaises(PathValidationError):
                    validate_path(ev, workspace=self.ws_dir)
                with self.assertRaises(PathValidationError):
                    validate_path(f"sub/{ev}", workspace=self.ws_dir)

    # h) validate_path(workspace_root) -> default me deny; allow_root=True ke saath allow
    def test_workspace_root_allow_root_flag(self):
        # Default: allow_root=False -> deny
        with self.assertRaises(PathValidationError):
            validate_path(".", workspace=self.ws_dir)
        with self.assertRaises(PathValidationError):
            validate_path(self.ws_dir, workspace=self.ws_dir)
        with self.assertRaises(PathValidationError):
            validate_path(self.ws_dir, workspace=self.ws_dir, allow_root=False)

        # allow_root=True -> allow
        res = validate_path(".", workspace=self.ws_dir, allow_root=True)
        self.assertEqual(res, Path(os.path.realpath(self.ws_dir)))
        res_abs = validate_path(self.ws_dir, workspace=self.ws_dir, allow_root=True)
        self.assertEqual(res_abs, Path(os.path.realpath(self.ws_dir)))

    # i) naya file jo abhi bani nahi (allow) aur naya file jiska parent junction se bahar jaye (deny)
    def test_nonexistent_file_allowed_and_junction_parent_denied(self):
        # Naya file jo abhi bani nahi -> allow
        new_file = "non_existent_folder/non_existent_file.txt"
        res = validate_path(new_file, workspace=self.ws_dir)
        expected = Path(os.path.realpath(self.ws_dir)) / "non_existent_folder" / "non_existent_file.txt"
        self.assertEqual(str(res).lower(), str(expected).lower())

        # Naya file jiska parent junction se bahar jaye -> deny
        outside_dir = self.temp_path / "outside_dir_i"
        outside_dir.mkdir(parents=True, exist_ok=True)
        junction_path = self.ws_dir / "junction_outside"

        if not os.path.exists(junction_path):
            if os.name == "nt":
                cmd = f'cmd /c mklink /J "{junction_path}" "{outside_dir}"'
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if proc.returncode != 0:
                    self.skipTest(
                        f"Skipping junction test: OS refused mklink /J ({proc.stderr.strip() or proc.stdout.strip()})"
                    )
            else:
                try:
                    os.symlink(outside_dir, junction_path, target_is_directory=True)
                except OSError as e:
                    self.skipTest(f"Skipping junction test: symlink creation failed: {e}")

        with self.assertRaises(PathValidationError):
            validate_path(junction_path / "new_file_outside.txt", workspace=self.ws_dir)

        with self.assertRaises(PathValidationError):
            validate_path("junction_outside/nested/new_file_outside.txt", workspace=self.ws_dir)


if __name__ == "__main__":
    unittest.main()
