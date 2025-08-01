from __future__ import annotations

import datetime
import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

PfroRecord = TargetRecordDescriptor(
    "filesystem/windows/pfro",
    [
        ("datetime", "ts"),
        ("path", "path"),
        ("string", "operation"),
    ],
)


class PfroPlugin(Plugin):
    """PFRO plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.logfile = self.target.resolve("%windir%/PFRO.log")

    def check_compatible(self) -> None:
        if not self.logfile.exists():
            raise UnsupportedPluginError("No PFRO log found")

    @export(record=PfroRecord)
    def pfro(self) -> Iterator[PfroRecord]:
        """Return the content of %windir%/PFRO.log

        A Pending File Rename Operation log file (PFRO.log) holds information about the process of deleting or renaming
        files that are locked or being used and that will be renamed on reboot. This is related to the filerenameop
        plugin.

        References:
            - https://social.technet.microsoft.com/Forums/en-US/9b66a7b0-16d5-4d22-be4e-51df12db9f80/issue-understanding-pfro-log
            - https://community.ccleaner.com/topic/49106-pending-file-rename-operations-log/

        Yields PfroRecords with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The parsed timestamp.
            path (uri): The parsed path.
            operation (string): The parsed operation.
        """
        target_tz = self.target.datetime.tzinfo

        try:
            for line in self.logfile.open("rt", encoding="utf-16-le"):
                if len(line) <= 1:
                    continue

                idx = line.split(" - ")
                date = idx[0]
                if "Error" in date:
                    # prfo log can log its own error. This results in an entry
                    # which gets grouped with the datetime of the logged
                    # action.
                    date = re.split(".+[A-Za-z]", date)[1]
                file_path = idx[1].split("|")[0][16:-2]
                operation = idx[1].split("|")
                operation = operation[1].split(" ")[0] if len(operation) >= 2 else None

                yield PfroRecord(
                    ts=datetime.datetime.strptime(date, "%m/%d/%Y %H:%M:%S").replace(tzinfo=target_tz),
                    path=self.target.fs.path(file_path),
                    operation=operation,
                    _target=self.target,
                )
        except UnicodeDecodeError:
            pass
