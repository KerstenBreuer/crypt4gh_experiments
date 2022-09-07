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


from typing import Tuple


def run():
    """
    TODO:
    Add logic to first start upload and then download
    """


def interrogation_room_upload(file_location: str, checksum: str):
    """
    TODO:
    Implement based on requirements in
    Prototype Script 1/3: Interrogation Room (Upload) GDEV-1238
    """


def encryption_key_store_upload(file_part: bytes) -> Tuple[str, str, int]:
    """
    TODO:
    Implement based on requirements in
    Prototype Script 2/3: Encryption Key Store (Upload) GDEV-1239
    """

    # request crypt4gh private key (subfunction)

    get_cryp4gh_private_key()

    # get envelope

    # decrypt envelope, get secret

    # generate ID (sha256)

    # deterine offset

    # reply with: secret, secret id, offset

    return "", "", 0


def encryption_key_store_download():
    """
    TODO:
    Implement based on requirements in
    Prototype Script 3/3: Encryption Key Store (Download) GDEV-1240
    """


def get_cryp4gh_private_key():

    return "input_files/"


if __name__ == "__main__":
    run()
