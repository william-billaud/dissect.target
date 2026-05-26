from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import BufferedStream

from dissect.target.containers.raw import RawContainer
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.windows_drive import _windows_get_disk_size

log = get_logger(__name__)


if TYPE_CHECKING:
    from pathlib import Path


class WindowsDrive(RawContainer):
    __type__ = "win_drive"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        if hasattr(fh, "read"):
            raise TypeError("Windows Drive can only be opened by path")

        disk_size = _windows_get_disk_size(str(fh))
        super().__init__(BufferedStream(
                            open(str(fh), "rb"),  # noqa: PTH123, SIM115
                            size=disk_size,
                        ), *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return False

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        print(f"Path to detect : {path}")
        return True
