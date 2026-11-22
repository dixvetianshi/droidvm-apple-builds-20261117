"""Exercise the real build-command runner's process-group cleanup on Linux."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from build_hostshare_component_ci import OwnedCommandTimeout, run_logged

CHILD = r'''
import pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
p = pathlib.Path(sys.argv[1])
while True:
    with p.open('ab') as stream:
        stream.write(b'x')
    time.sleep(0.02)
'''

PARENT = r'''
import pathlib, signal, subprocess, sys, time
if sys.argv[3] == 'ignore':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])
pathlib.Path(sys.argv[2] + '.pid').write_text(str(child.pid))
while True:
    time.sleep(0.02)
'''


class BuildCommandLifecycleTest(unittest.TestCase):
    def test_completed_command_retains_exact_log(self):
        with tempfile.TemporaryDirectory(prefix='build-command-success-') as temporary:
            log = Path(temporary) / 'command.log'
            run_logged([sys.executable, '-c', "print('complete')"], log, timeout=10)
            self.assertEqual(log.read_text().strip(), 'complete')

    @unittest.skipUnless(os.name == 'posix' and Path('/proc').is_dir(), 'Linux process-group regression')
    def test_timeout_stops_child_when_parent_ignores_term(self):
        self.check_timeout('ignore')

    @unittest.skipUnless(os.name == 'posix' and Path('/proc').is_dir(), 'Linux process-group regression')
    def test_timeout_stops_child_when_parent_exits_first(self):
        self.check_timeout('exit')

    def check_timeout(self, mode):
        with tempfile.TemporaryDirectory(prefix='build-command-timeout-') as temporary:
            directory = Path(temporary)
            heartbeat = directory / 'heartbeat'
            log = directory / 'command.log'
            with self.assertRaises(OwnedCommandTimeout) as caught:
                run_logged([sys.executable, '-c', PARENT, CHILD, str(heartbeat), mode], log, timeout=0.8)
            self.assertTrue(caught.exception.cleanup_complete)
            self.assertTrue(heartbeat.is_file(), 'The descendant must really have run')
            size = heartbeat.stat().st_size
            time.sleep(0.15)
            self.assertEqual(heartbeat.stat().st_size, size, 'The timed-out descendant is still writing')
            pid = int(Path(str(heartbeat) + '.pid').read_text())
            try:
                raw = Path(f'/proc/{pid}/stat').read_text()
            except FileNotFoundError:
                return
            self.assertIn(raw[raw.rfind(')') + 2:].split()[0], ('Z', 'X'), 'The descendant is still executing')


if __name__ == '__main__':
    unittest.main()
