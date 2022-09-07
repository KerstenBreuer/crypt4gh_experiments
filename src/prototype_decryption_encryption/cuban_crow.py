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
"""
Prototype encryption/decryption (Cuban Crow) script.
One base function for each part/ticket, extensible with required subfunctions.
Hardcode responses at non-implemented boundaries.
"""
import filecmp
import hashlib
import io
from pathlib import Path
from sys import stderr
from typing import NamedTuple, Optional, Tuple


import crypt4gh.header  # type: ignore
import crypt4gh.keys  # type: ignore
from crypt4gh import lib  # type: ignore
from crypt4gh.lib import CIPHER_SEGMENT_SIZE  # type: ignore

SRC_DIR = Path(__file__).parent.parent.resolve().absolute()
FILES_DIR = SRC_DIR.parent.resolve() / "input_files"


class Header(NamedTuple):
    """Contains the content of a header"""

    session_keys: list[bytes]  # this is the enryption secret for the file
    edit_list: Optional[object]


INDIR = Path(__file__).parent.parent.parent / "input_files"
OUTDIR = Path(__file__).parent.parent.parent / "output_files"
PART_SIZE = 16 * 1024**2


def run():
    """
    TODO:
    Add logic to first start upload and then download
    """
    interrogation_room_upload(
        file_location=INDIR / "50MiB.fasta.c4gh",
        checksum="3e67802e821306fe287b85001dbab213a3eb4d2560702c5740741e5111c97841",
    )


def interrogation_room_upload(*, file_location: Path, checksum: str):
    """
    Forwards first file part to encryption key store, retrieves file encryption
    secret(s) (K_data), decrypts file and computes checksums
    See: Prototype Script 1/3: Interrogation Room (Upload) GDEV-1238
    """
    with file_location.open("rb") as source:
        # first_part = source.read(PART_SIZE)
        _ = source.read(PART_SIZE)

    # fixme: Placeholder. Replace with call to implementation when 1239 is ready
    encryption_secret = b'(\xb6`\xdb\x9fR\xda\xa7"\xb7d\xb2\xf7\x03\xba=\xfe\xd4\xf2\xd8\x13\xae\x885X\xdf\xf7]\xcdL\x03K'
    offset = 124
    # encryption_secret, encryption_secret_id, offset = encryption_key_store_upload(
    #     file_part=first_part
    # )
    part_checksums, total_checksum = compute_checksums(
        file_location=file_location, secret=encryption_secret, offset=offset
    )
    if total_checksum == checksum:
        print(f"Checksum '{checksum}' correctly validated")
    else:
        print(f"Checksum mismatch!\nExpected: '{checksum}'\nActual: '{total_checksum}'")
    if not filecmp.cmp(INDIR / "50MiB.fasta", OUTDIR / "decrypted_content"):
        print("Source file and decrypted file content mismatch", file=stderr)


def compute_checksums(
    *, file_location: Path, secret: bytes, offset: int
) -> Tuple[list[str], str]:
    """
    Iterate over actual content in the file, reading encrypted content starting at the
    given offset. Consume CIPHER_SEGMENT_SIZE bytes at a time, compute part checksum,
    decrypt the part content and update checksum of the whole unencrypted content
    """
    file = file_location.resolve()

    if not OUTDIR.exists():
        OUTDIR.mkdir()
    outpath = OUTDIR / "decrypted_content"

    total_checksum = hashlib.sha256()
    encrypted_part_checksums = []

    with file.open("rb") as source:
        with outpath.open("wb") as outfile:
            source.seek(offset)
            part = source.read(CIPHER_SEGMENT_SIZE)
            while part:
                part_checksum = hashlib.sha256(part).hexdigest()
                encrypted_part_checksums.append(part_checksum)

                decrypted = lib.decrypt_block(ciphersegment=part, session_keys=[secret])

                total_checksum.update(decrypted)
                outfile.write(decrypted)
                part = source.read(CIPHER_SEGMENT_SIZE)

    return encrypted_part_checksums, total_checksum.hexdigest()


def encryption_key_store_upload(file_part: bytes) -> Tuple[str, str, int]:
    """
    Encryption key store functionality:
    Extract header envelope from the first file part
    Decrypt header & extract key
    Return key, key id and offset
    """

    file_stream = io.BytesIO(file_part)

    # request crypt4gh private key
    ghga_sec = request_cryp4gh_private_key()
    ghga_keys = [(0, ghga_sec, None)]

    session_keys, __ = crypt4gh.header.deconstruct(
        file_stream,
        keys=ghga_keys,
    )

    # retrieve session key, offset and generate hash id of session key
    session_key = session_keys[0]
    content_start = file_stream.tell()
    session_key_id = hashlib.sha256(session_key).hexdigest()

    return session_key, session_key_id, content_start


def encryption_key_store_download():
    """
    TODO:
    Implement based on requirements in
    Prototype Script 3/3: Encryption Key Store (Download) GDEV-1240
    """


def request_cryp4gh_private_key() -> str:
    """Returns the ghga private key"""

    # get secret ghga key:
    ghga_sec = crypt4gh.keys.get_private_key(
        FILES_DIR.resolve() / "ghga.sec", lambda: None
    )

    return ghga_sec


if __name__ == "__main__":
    run()
