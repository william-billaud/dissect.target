from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, BufferedStream

from dissect.target.container import Container
from dissect.target.helpers.logging import get_logger

log = get_logger(__name__)


if TYPE_CHECKING:
    from pathlib import Path


class RawContainer(Container):
    __type__ = "raw"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        log
        if not hasattr(fh, "read"):
            fh = fh.open("rb")

        if not hasattr(fh, "size"):
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(0)
        elif callable(fh.size):
            size = fh.size()
        else:
            size = fh.size

        if not isinstance(fh, AlignedStream):
            fh = BufferedStream(fh, size=size)

        self.read = fh.read
        self.seek = fh.seek
        self.tell = fh.tell
        self.close = fh.close

        super().__init__(fh, size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return True

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return True
