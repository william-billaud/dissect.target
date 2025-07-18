from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_field = re.compile(r"(.+)=(.+)")

COMMON_ELEMENTS = [
    ("datetime", "start_time"),
    ("datetime", "stop_time"),
    ("datetime", "created"),
    ("datetime", "modified"),
    ("datetime", "access"),
    ("path", "path"),
    ("path", "filename"),
    ("path", "create"),
    ("varint", "size"),
    ("string", "magic"),
    ("string", "size_of_image"),
    ("varint", "pe_checksum"),
    ("datetime", "link_date"),
    ("string", "linker_version"),
    ("string", "bin_file_version"),
    ("string", "bin_product_version"),
    ("string", "binary_type"),
    ("digest", "digest"),
    ("wstring", "file_version"),
    ("wstring", "company_name"),
    ("wstring", "file_description"),
    ("wstring", "legal"),
    ("string", "original_filename"),
    ("wstring", "product_name"),
    ("string", "product_version"),
    ("string", "pe_image"),
    ("string", "pe_subsystem"),
    ("string", "crc_checksum"),
    ("filesize", "filesize"),
    ("wstring", "longname"),
    ("string", "msi"),
]

AmcacheFileCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install/file_create",
    COMMON_ELEMENTS,
)

AmcacheArpCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install/arp_create",
    COMMON_ELEMENTS,
)


def _to_log_timestamp(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc)


def create_record(
    description: AmcacheFileCreateRecord | AmcacheArpCreateRecord,
    filename: str,
    install_properties: dict[str, str],
    create: str,
    target: Target,
) -> TargetRecordDescriptor:
    return description(
        start_time=_to_log_timestamp(install_properties.get("starttime")),
        stop_time=_to_log_timestamp(install_properties.get("stoptime")),
        created=_to_log_timestamp(install_properties.get("created")),
        modified=_to_log_timestamp(install_properties.get("modified")),
        access=_to_log_timestamp(install_properties.get("lastaccessed")),
        link_date=_to_log_timestamp(install_properties.get("linkdate")),
        path=target.fs.path(install_properties.get("path")),
        filename=target.fs.path(filename),
        create=target.fs.path(create),
        size_of_image=install_properties.get("sizeofimage"),
        file_description=install_properties.get("filedescription"),
        size=int(install_properties.get("size", "0x00"), 16),
        digest=(
            None,
            install_properties.get("id")[4:],
            None,
        ),  # remove leading zeros from the entry to create a sha1 hash
        company_name=install_properties.get("companyname"),
        binary_type=install_properties.get("binarytype"),
        bin_product_version=install_properties.get("binproductversion"),
        bin_file_version=install_properties.get("binfileversion"),
        filesize=int(install_properties.get("filesize", "0"), 16),
        pe_image=install_properties.get("peimagetype"),
        product_version=install_properties.get("productversion"),
        crc_checksum=install_properties.get("crcchecksum"),
        legal=install_properties.get("legalcopyright"),
        magic=install_properties.get("magic"),
        linker_version=install_properties.get("linkerversion"),
        product_name=install_properties.get("productname"),
        pe_subsystem=install_properties.get("pesubsystem"),
        longname=install_properties.get("longname"),
        pe_checksum=int(install_properties.get("pechecksum", "0x00"), 16),
        _target=target,
    )


class AmcacheInstallPlugin(Plugin):
    """Amcache install log plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.logs = self.target.resolve("%windir%/appcompat/programs/install")

    def check_compatible(self) -> None:
        if not self.logs.exists():
            raise UnsupportedPluginError("No amcache install logs found")

    @export(record=[AmcacheArpCreateRecord, AmcacheFileCreateRecord])
    def amcache_install(self) -> Iterator[AmcacheArpCreateRecord, AmcacheFileCreateRecord]:
        """Return the contents of the Amcache install log.

        The log file contains the changes an installer performed on the system.
        These only get created when the executable is an installer.
        """
        for f in self.logs.iterdir():
            install_properties = {}
            arp_created = []
            file_created = []
            for line in f.read_text("utf-16-le").splitlines():
                match = re_field.match(line.rstrip())
                if not match:
                    continue

                if match.group(1) == "FileCreate":
                    file_created.append(match.group(2))

                elif match.group(1) == "ArpCreate":
                    arp_created.append(match.group(2))

                else:
                    install_properties[match.group(1).lower()] = match.group(2)

            filename = str(f)
            for arp_create in arp_created:
                yield create_record(
                    AmcacheArpCreateRecord,
                    filename=filename,
                    install_properties=install_properties,
                    create=arp_create,
                    target=self.target,
                )
            for file_create in file_created:
                yield create_record(
                    AmcacheFileCreateRecord,
                    filename=filename,
                    install_properties=install_properties,
                    create=file_create,
                    target=self.target,
                )
