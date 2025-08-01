from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from defusedxml import ElementTree

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

# Example startupinfo entry:
#
#    <Process Name="C:\Windows\System32\SecurityHealthSystray.exe" PID="6208" StartedInTraceSec="48.500">
#    	<StartTime>2020/09/11:18:12:48.6685573</StartTime>
#    	<CommandLine><![CDATA["C:\Windows\System32\SecurityHealthSystray.exe" ]]></CommandLine>
#    	<DiskUsage Units="bytes">325120</DiskUsage>
#    	<CpuUsage Units="us">32024</CpuUsage>
#    	<ParentPID>6016</ParentPID>
#    	<ParentStartTime>2020/09/11:18:12:30.2666535</ParentStartTime>
#    	<ParentName>explorer.exe</ParentName>
#    </Process>

StartupInfoRecord = TargetRecordDescriptor(
    "filesystem/windows/startupinfo",
    [
        ("datetime", "ts"),
        ("path", "path"),
        ("path", "commandline"),
        ("varint", "pid"),
        ("varint", "parent_pid"),
        ("datetime", "parent_start_time"),
        ("path", "parent_name"),
        ("varint", "disk_usage"),
        ("varint", "cpu_usage"),
    ],
)


def parse_ts(time_string: str) -> datetime.datetime | None:
    if not time_string:
        return None

    return datetime.datetime.strptime(time_string[:26], "%Y/%m/%d:%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)


class StartupInfoPlugin(Plugin):
    """Windows startup info plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._files = []

        path = target.resolve("%windir%/system32/wdi/logfiles/startupinfo")
        if path.exists():
            self._files = list(path.iterdir())

    def check_compatible(self) -> None:
        if not self._files:
            raise UnsupportedPluginError("No StartupInfo files found")

    @export(record=StartupInfoRecord)
    def startupinfo(self) -> Iterator[StartupInfoRecord]:
        """Return the contents of StartupInfo files.

        On a Windows system, the StartupInfo log files contain information about process execution for the first 90
        seconds of user logon activity, such as process name and CPU usage.

        References:
            - https://www.trustedsec.com/blog/who-left-the-backdoor-open-using-startupinfo-for-the-win/
        """
        for path in self._files:
            fh = path.open("rb")

            try:
                root = ElementTree.fromstring(fh.read().decode("utf-16-le"), forbid_dtd=True)
                for process in root.iter("Process"):
                    start_time = process.findtext("StartTime")
                    parent_start_time = process.findtext("ParentStartTime")

                    yield StartupInfoRecord(
                        ts=parse_ts(start_time),
                        path=self.target.fs.path(process.get("Name")),
                        commandline=self.target.fs.path(process.findtext("CommandLine")),
                        pid=process.get("PID"),
                        parent_pid=process.findtext("ParentPID"),
                        parent_start_time=parse_ts(parent_start_time),
                        parent_name=self.target.fs.path(process.findtext("ParentName")),
                        disk_usage=process.findtext("DiskUsage"),
                        cpu_usage=process.findtext("CpuUsage"),
                        _target=self.target,
                    )
            except Exception:
                self.target.log.exception("Failed to open StartupInfo file: %s", str(path))
