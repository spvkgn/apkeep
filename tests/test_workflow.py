"""Validate CI fixture prerequisites and rustup flags without downloads."""
from pathlib import Path
import re
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OfflineFixtureWorkflowTests(unittest.TestCase):
    def test_runner_is_pinned_to_ubuntu_22_04(self):
        workflow = (ROOT / '.github/workflows/tests.yml').read_text()
        self.assertEqual(re.findall(r'^\s+runs-on: (\S+)\s*$', workflow, re.MULTILINE),
                         ['ubuntu-22.04'])

    def test_fixture_packages_are_installed_before_cargo_tests(self):
        workflow = (ROOT / '.github/workflows/tests.yml').read_text()
        update = re.search(r'^\s+sudo apt-get update\s*$', workflow, re.MULTILINE)
        install = re.search(r'^\s+sudo apt-get install ([^\n]+)$', workflow, re.MULTILINE)
        cargo_test = re.search(r'^\s+run: cargo \+stable test\b', workflow, re.MULTILINE)
        if update is None:
            self.fail('refresh apt metadata before installing fixtures')
        if install is None:
            self.fail('install offline APK fixture prerequisites')
        if cargo_test is None:
            self.fail('keep the all-targets Rust test step')
        packages = shlex.split(install.group(1))
        for package in ('aapt', 'libandroid-23-java', 'apksigner', 'default-jdk-headless'):
            with self.subTest(package=package):
                self.assertIn(package, packages)
        self.assertIn('-y', packages, 'apt installation must be noninteractive')
        self.assertLess(update.start(), install.start())
        self.assertLess(install.start(), cargo_test.start())


class RustupWorkflowTests(unittest.TestCase):
    def test_installer_flags_are_supported_by_selected_rustup_subcommand(self):
        lines = (ROOT / '.github/workflows/tests.yml').read_text().splitlines()
        commands = [shlex.split(line.strip()[len('run: '):]) for line in lines
                    if line.strip().startswith('run: rustup ')]
        self.assertEqual(len(commands), 1, 'expected one Rust toolchain setup command')
        command = commands[0]
        prefix = command[:command.index('stable')]
        result = subprocess.run(prefix + ['--help'], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        for flag in (arg for arg in command if arg.startswith('--')):
            self.assertIn(flag, result.stdout, f'{flag} not supported by {prefix}')
        self.assertIn('clippy', command)
        self.assertIn('minimal', command)


if __name__ == '__main__':
    unittest.main()
