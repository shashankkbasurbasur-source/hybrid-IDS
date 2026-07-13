"""
Generic tail -f style file watcher. Follows a log file continuously,
including across log rotation (detects inode change and reopens).
"""

import os
import time


class LogFileWatcher:
    def __init__(self, filepath, poll_interval=1.0, from_end=True):
        self.filepath = filepath
        self.poll_interval = poll_interval
        self.from_end = from_end
        self._fh = None
        self._inode = None

    def _open(self):
        self._fh = open(self.filepath, "r")
        if self.from_end:
            self._fh.seek(0, os.SEEK_END)
        self._inode = os.fstat(self._fh.fileno()).st_ino

    def _reopen_if_rotated(self):
        try:
            current_inode = os.stat(self.filepath).st_ino
        except FileNotFoundError:
            return
        if current_inode != self._inode:
            self._fh.close()
            self._open()

    def tail(self):
        self._open()
        while True:
            line = self._fh.readline()
            if not line:
                time.sleep(self.poll_interval)
                self._reopen_if_rotated()
                continue
            yield line.rstrip("\n")

    def stop(self):
        if self._fh:
            self._fh.close()