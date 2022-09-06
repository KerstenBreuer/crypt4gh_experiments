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
"""Script for test file generation"""

from functools import partial
from getpass import getpass
from pathlib import Path

from crypt4gh import lib  # type: ignore
from crypt4gh.keys import get_private_key, get_public_key  # type: ignore

HEADER = ">ABC DNA"
NUCLEOBASES = ("A", "T", "G", "C")
FILE_DIR = Path(__file__).parent.parent.parent / "input_files"


def generate():
    """Generate and encrypt file with provided keys"""
    if not FILE_DIR.exists():
        FILE_DIR.mkdir()

    # generate unencrypted test file
    unencrypted = FILE_DIR / "50MiB.fasta"

    with unencrypted.open("w", encoding="utf-8") as file:
        file.write(f"{HEADER}\n")
        # should result in ~ 50MiB for 80 chars a line
        for _ in range(647270):
            file.write(f"{fixed_line()}\n")

    # get encryption keys
    pk_location = (FILE_DIR / "receiver.pub").resolve()
    public_key = get_public_key(pk_location)

    sk_location = (FILE_DIR / "sender.sec").resolve()
    # copied from crypt4gh cli
    callback = partial(getpass, prompt=f"Passphrase for {sk_location}: ")
    secret_key = get_private_key(sk_location, callback)

    # encrypt test file using crypt4gh
    encrypted = FILE_DIR / "50MiB.fasta.c4gh"

    recipient_keys = [(0, secret_key, public_key)]

    # lib.encrypt expects file-like objects
    with unencrypted.open("rb") as infile:
        with encrypted.open("wb") as outfile:
            lib.encrypt(keys=recipient_keys, infile=infile, outfile=outfile)


def fixed_line():
    """We need fixed output for reproducibility, i.e provide one fixe line"""
    return "CTAATTGTTTCCGGGATAGACCGGGGCCACCTATGGTGAATTTGGGGACTCAGAACAACAGACTTGGCGACTTCGTCTAT"


if __name__ == "__main__":
    generate()
