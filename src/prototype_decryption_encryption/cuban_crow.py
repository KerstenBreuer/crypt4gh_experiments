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
import hashlib
import io
import shutil
import sys
from pathlib import Path
from typing import NamedTuple, Optional, Tuple

import crypt4gh.header  # type: ignore
import crypt4gh.keys  # type: ignore
import crypt4gh.lib  # type: ignore
from crypt4gh.lib import CIPHER_SEGMENT_SIZE  # type: ignore

ROOT_DIR = Path(__file__).parent.parent.parent.resolve()
INPUT_DIR = ROOT_DIR / "input_files"
OUTPUT_DIR = ROOT_DIR / "output_files"
PART_SIZE = 16 * 1024**2

SESSION_KEY = ""


class Header(NamedTuple):
    """Contains the content of a header"""

    session_keys: list[bytes]  # this is the enryption secret for the file
    edit_list: Optional[object]


def run():
    """
    Logic to start simulated upload and then download
    """
    checksum = "3e67802e821306fe287b85001dbab213a3eb4d2560702c5740741e5111c97841"
    interrogation_room_upload(
        file_location=INPUT_DIR / "50MiB.fasta.c4gh",
        checksum=checksum,
    )
    download(checksum=checksum)


def interrogation_room_upload(*, file_location: Path, checksum: str):
    """
    Forwards first file part to encryption key store, retrieves file encryption
    secret(s) (K_data), decrypts file and computes checksums
    See: Prototype Script 1/3: Interrogation Room (Upload) GDEV-1238
    """
    with file_location.open("rb") as source:
        first_part = source.read(PART_SIZE)

    encryption_secret, encryption_secret_id, offset = encryption_key_store_upload(
        file_part=first_part
    )
    part_checksums, total_checksum = compute_checksums(
        file_location=file_location, secret=encryption_secret, offset=offset
    )
    if total_checksum == checksum:
        print(f"Checksum '{checksum}' correctly validated")
    else:
        print(f"Checksum mismatch!\nExpected: '{checksum}'\nActual: '{total_checksum}'")
    print(
        f"Part checksums: {part_checksums}\nEncryption secret id: {encryption_secret_id}"
    )


def compute_checksums(
    *, file_location: Path, secret: str, offset: int
) -> Tuple[list[str], str]:
    """
    Iterate over actual content in the file, reading encrypted content starting at the
    given offset. Consume CIPHER_SEGMENT_SIZE bytes at a time, compute part checksum,
    decrypt the part content and update checksum of the whole unencrypted content
    """
    file = file_location.resolve()

    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir()
    outpath = OUTPUT_DIR / "encrypted_content"

    total_checksum = hashlib.sha256()
    encrypted_part_checksums = []

    with file.open("rb") as source:
        with outpath.open("wb") as outfile:
            source.seek(offset)
            part = source.read(CIPHER_SEGMENT_SIZE)
            while part:
                outfile.write(part)

                part_checksum = hashlib.sha256(part).hexdigest()
                encrypted_part_checksums.append(part_checksum)

                decrypted = crypt4gh.lib.decrypt_block(
                    ciphersegment=part, session_keys=[secret]
                )
                total_checksum.update(decrypted)

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

    global SESSION_KEY
    SESSION_KEY = session_key

    return session_key, session_key_id, content_start


def encryption_key_store_download():
    """
    Retrieve GHGA secret key, user 1+2 public keys and create personalized envelope
    See: Prototype Script 3/3: Encryption Key Store (Download) GDEV-1240
    """
    # get ghga private key and user public keys
    ghga_secret = crypt4gh.keys.get_private_key(INPUT_DIR / "ghga.sec", lambda: None)
    pub_keys = [
        crypt4gh.keys.get_public_key(INPUT_DIR / "researcher_1.pub"),
        crypt4gh.keys.get_public_key(INPUT_DIR / "researcher_2.pub"),
    ]
    keys = [(0, ghga_secret, pub_key) for pub_key in pub_keys]
    header_content = crypt4gh.header.make_packet_data_enc(0, SESSION_KEY)
    header_packets = crypt4gh.header.encrypt(header_content, keys)
    header_bytes = crypt4gh.header.serialize(header_packets)
    return header_bytes


def request_cryp4gh_private_key() -> str:
    """Returns the ghga private key"""

    # get secret ghga key:
    ghga_sec = crypt4gh.keys.get_private_key(INPUT_DIR / "ghga.sec", lambda: None)

    return ghga_sec


def download(*, checksum: str):
    """
    Generate envelope for two users, contcatenat with encrypted content,
    decrypt content for both users separatly and verify checksum
    """
    envelope = encryption_key_store_download()
    file_path = OUTPUT_DIR / "encrypted_content"

    downloaded_file = OUTPUT_DIR / "downloaded_file"

    with file_path.open("rb") as encrypted_content:
        with downloaded_file.open("wb") as file:
            file.write(envelope)
            shutil.copyfileobj(encrypted_content, file)

    ghga_public = crypt4gh.keys.get_public_key(INPUT_DIR / "ghga.pub")
    secret_keys = [
        crypt4gh.keys.get_private_key(INPUT_DIR / "researcher_1.sec", lambda: None),
        crypt4gh.keys.get_private_key(INPUT_DIR / "researcher_2.sec", lambda: None),
    ]
    outfile_1 = OUTPUT_DIR / "decrypted_content_1"
    outfile_2 = OUTPUT_DIR / "decrypted_content_2"

    # explicitly check decryption with both keys
    with downloaded_file.open("rb") as infile:
        with outfile_1.open("wb") as outfile:
            crypt4gh.lib.decrypt(
                keys=[(0, secret_keys[0], ghga_public)],
                infile=infile,
                outfile=outfile,
            )

        # Rewind input file
        infile.seek(0)
        with outfile_2.open("wb") as outfile:
            crypt4gh.lib.decrypt(
                keys=[(0, secret_keys[1], ghga_public)],
                infile=infile,
                outfile=outfile,
            )

    # checksum validation
    for outpath in [outfile_1, outfile_2]:
        with outpath.open("rb") as file:
            computed_checksum = hashlib.sha256(file.read()).hexdigest()
            if checksum != computed_checksum:
                print(
                    f"Checksum mismatch for '{outpath}'\nExpected: {checksum}\nActual: {computed_checksum}",
                    file=sys.stderr,
                )
            else:
                print(f"Checksum works for {outpath}")


if __name__ == "__main__":
    run()
