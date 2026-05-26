from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import BufferedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.windows_drive import _windows_get_disk_size

log = get_logger(__name__)


if TYPE_CHECKING:
    from pathlib import Path


def is_physical_drive_path(path: str) -> bool:
    r"""Check if path match a logical drive path, E.g : \\.\PhysicalDrive1 ."""
    return re.fullmatch(r"\\\\.\\+PhysicalDrive[0-9]+", path, re.IGNORECASE) is not None


def is_logical_drive_path(path: str) -> bool:
    r"""Check if path match a logical drive path, E.g : \\.\C: or \\.\\\Z: ."""
    return re.fullmatch(r"\\\\.\\+[a-z]:", path, re.IGNORECASE) is not None


class WindowsDrive(RawContainer):
    r"""Allows to load windows drive, such as \\.\C: or "\\.\PhysicalDrive1 ."""

    __type__ = "windows_drive"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        if hasattr(fh, "read"):
            raise TypeError("Windows Drive can only be opened by path")
        if sys.platform != "win32":
            raise TypeError("Windows Drive is only available on Windows plateform.")
        disk_size = _windows_get_disk_size(str(fh))
        super().__init__(
            BufferedStream(
                open(str(fh), "rb"),  # noqa: PTH123, SIM115
                size=disk_size,
            ),
            *args,
            **kwargs,
        )

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return False

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        if sys.platform != "win32":
            return False
        # return path.drive == "\\\\.\\"
        return is_physical_drive_path(str(path)) or is_logical_drive_path(str(path))
