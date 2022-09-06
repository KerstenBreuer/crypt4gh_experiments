#!/usr/bin/env python3

# Copyright 2022 Universität Tübingen, DKFZ and EMBL
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Demonstrates how to read the header and decrypt the file."""

import os
from pathlib import Path
from typing import NamedTuple, Optional

import crypt4gh.header  # type: ignore
import crypt4gh.keys  # type: ignore

SRC_DIR = Path(__file__).parent.parent.resolve().absolute()
EXAMPLE_DATA_DIR = SRC_DIR.parent.resolve() / "example_data"


class Header(NamedTuple):
    """Contains the content of a header"""

    session_keys: list[bytes]  # this is the enryption secret for the file
    edit_list: Optional[object]


def read_header() -> tuple[Header, int]:
    """Split off the Crypt4GH header, decrypt it, and return a Header object
    and the position where the content starts."""

    # get secret receiver key and public sender key:
    receiver_sec = crypt4gh.keys.get_private_key(
        EXAMPLE_DATA_DIR / "receiver.sec", lambda: None
    )
    receiver_keys = [(0, receiver_sec, None)]

    with open(EXAMPLE_DATA_DIR / "big-file.fasta.c4gh", "rb") as file:
        session_keys, edit_list = crypt4gh.header.deconstruct(
            file,
            keys=receiver_keys,
        )
        header = Header(session_keys=session_keys, edit_list=edit_list)

        content_start = file.tell()

    return header, content_start


def remove_header_from_file():
    """Decrypt the big fasta file."""

    _, content_start = read_header()

    encrypted_file_path = EXAMPLE_DATA_DIR / "big-file.fasta.c4gh"
    decrypted_file_path = EXAMPLE_DATA_DIR / "big-file.fasta.c4gh.headerless"

    with open(encrypted_file_path, "rb") as encrypted_file:

        encrypted_file.seek(content_start)

        if os.path.isfile(decrypted_file_path):
            os.remove(decrypted_file_path)

        with open(decrypted_file_path, "wb") as decrypted_file:
            # write the content chunck-vise:
            while True:
                chunk = encrypted_file.read(1000)

                if not chunk:
                    break

                decrypted_file.write(chunk)


if __name__ == "__main__":
    remove_header_from_file()
