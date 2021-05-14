#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path
import zipfile

BYTES_IN_MB = 1024 * 1024

# config
REQUIRED_FILES = ["README", "guessword.c"]
MAX_ARCHIVE_SIZE = 5 * BYTES_IN_MB
MAX_UNCOMPRESSED_SIZE = 50 * BYTES_IN_MB


def print_banner(line):
    print("=" * len(line))
    print(line)
    print("=" * len(line))


def fail(msg):
    print_banner("Sanity check failed. :-(")
    print(msg)
    sys.exit(1)


def check_archive_size(archive_path):
    archive_size = archive_path.stat().st_size
    if archive_size > MAX_ARCHIVE_SIZE:
        size_in_mb = archive_size / BYTES_IN_MB
        fail(f"ZIP archive too large (max 5MB, got {size_in_mb:.2f}MB)")


def check_uncompressed_size(archive_path):
    with zipfile.ZipFile(archive_path, "r") as archive_file:
        total_size = 0
        for file_info in archive_file.infolist():
            total_size += file_info.file_size
        if total_size > MAX_UNCOMPRESSED_SIZE:
            fail(f"Uncompressed size is too large (max 200MB, got {total_size:.2f}MB)")


def find_missing_files(root_path, required_files):
    missing_files = []
    for name in required_files:
        file_path = root_path / name
        if not file_path.exists() or not file_path.is_file():
            missing_files.append(name)
    return missing_files


def check_readme_file(archive_root):
    readme_path = archive_root / "README"
    with readme_path.open("r") as readme_file:
        lines = [line.decode().strip() for line in readme_file]

    if len(lines) != 5:
        fail(f"invalid README: expected 5 lines, got {len(lines)}")

    hackerhandle, name, email, vunetid, studentid = lines

    if not re.match(r"^[a-zA-Z0-9]{3,16}$", hackerhandle):
        fail(
            f"Invalid hacker handle in README: {hackerhandle}\n"
            "\t- should only contain alphanumeric characters\n"
            "\t- should be 3-16 characters"
        )

    if not re.match(r"^[^@]*@.+\.[^.]+$", email):
        fail(f"Invalid email in README: {email}")

    if not re.match(r"^[a-z]{3}[0-9]{3}$", vunetid):
        fail(f"Invalid vunetid in README: {vunetid}")


def main(args):
    if not zipfile.is_zipfile(args.archive_path):
        fail("The path provided does not point to a ZIP file")

    check_archive_size(args.archive_path)
    check_uncompressed_size(args.archive_path)

    archive_root = zipfile.Path(args.archive_path)

    missing_files = find_missing_files(archive_root, REQUIRED_FILES)
    if missing_files:
        fail(
            f"Please provide the following files: {missing_files}\n"
            "\t- make sure that the files are stored in the right path,\n"
            "\t  usually the root of the archive"
        )

    check_readme_file(archive_root)

    # all checks succeeded
    print_banner("Sanity check passed. OK!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("archive_path", type=Path)
    args = parser.parse_args()

    main(args)
