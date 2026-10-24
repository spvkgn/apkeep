"""Real PTY regressions; synthetic invalid token/cancellation never reach a store."""
import fcntl
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import termios
import time
import unittest


@unittest.skipUnless(os.name == 'posix', 'POSIX PTY regression')
class CredentialTerminalTests(unittest.TestCase):
    def exercise(self, payload, expected_code):
        binary = Path(os.environ.get('APKEEP_TEST_BINARY', 'target/debug/apkeep')).resolve()
        self.assertTrue(binary.is_file(), 'build the binary and set APKEEP_TEST_BINARY')
        master, slave = os.openpty()
        original = termios.tcgetattr(slave)
        child = None
        try:
            with tempfile.TemporaryDirectory() as home:
                def setup():
                    os.setsid()
                    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                child = subprocess.Popen([str(binary), '-d', 'google-play', '-a',
                    'com.example.app', '-e', 'fixture@example.invalid', '.'],
                    stdin=slave, stdout=slave, stderr=slave, cwd=home, preexec_fn=setup,
                    env=os.environ | {'HOME': home, 'XDG_CONFIG_HOME': home,
                        'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1'})
                data = bytearray()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.02)[0]:
                        data.extend(os.read(master, 65536))
                    if b'AAS Token (or AUTH Token): ' in data and not termios.tcgetattr(slave)[3] & termios.ECHO:
                        break
                self.assertIn(b'AAS Token (or AUTH Token): ', data)
                self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
                os.write(master, payload)
                child.wait(timeout=5)
                while select.select([master], [], [], 0.02)[0]:
                    data.extend(os.read(master, 65536))
                self.assertEqual(child.returncode, expected_code)
                self.assertEqual(termios.tcgetattr(slave), original, 'terminal state not fully restored')
                self.assertNotIn(b'NEVER_ECHO_THIS_FIXTURE', data)
                return bytes(data)
        finally:
            if child is not None and child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            termios.tcsetattr(slave, termios.TCSANOW, original)
            os.close(master)
            os.close(slave)

    def test_invalid_token_disables_echo_restores_terminal_and_refuses_login(self):
        self.assertIn(b'Google Play token', self.exercise(b'NEVER_ECHO_THIS_FIXTURE invalid\n', 1))

    def test_ctrl_c_restores_terminal_before_sigint(self):
        self.exercise(b'\x03', -signal.SIGINT)

    def test_ctrl_d_restores_terminal_and_refuses_login(self):
        self.exercise(b'\x04', 1)


if __name__ == '__main__':
    unittest.main()
