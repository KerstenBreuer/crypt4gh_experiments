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

from pathlib import Path

from crypt4gh import lib  # type: ignore
from crypt4gh.keys import get_private_key, get_public_key  # type: ignore

HEADER = ">ABC DNA"
FILE_DIR = Path(__file__).parent.parent.parent.resolve() / "input_files"


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
    pk_location = (FILE_DIR / "ghga.pub").resolve()
    ghga_public = get_public_key(pk_location)

    sk_location = (FILE_DIR / "researcher_1.sec").resolve()
    user_1_secret = get_private_key(sk_location, lambda: None)

    sk_location = (FILE_DIR / "researcher_2.sec").resolve()
    user_2_secret = get_private_key(sk_location, lambda: None)

    # encrypt test file using crypt4gh
    encrypted = FILE_DIR / "50MiB.fasta.c4gh"

    user_keys = [(0, user_1_secret, ghga_public), (0, user_2_secret, ghga_public)]

    # lib.encrypt expects file-like objects
    with unencrypted.open("rb") as infile:
        with encrypted.open("wb") as outfile:
            lib.encrypt(keys=user_keys, infile=infile, outfile=outfile)


def fixed_line():
    """We need fixed output for reproducibility, i.e provide one fixe line"""
    return "CTAATTGTTTCCGGGATAGACCGGGGCCACCTATGGTGAATTTGGGGACTCAGAACAACAGACTTGGCGACTTCGTCTAT"


if __name__ == "__main__":
    generate()
