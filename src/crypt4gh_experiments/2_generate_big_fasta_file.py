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

"""Generates a big fake fasta file."""

import time
from functools import lru_cache
from pathlib import Path
from random import choice

SRC_DIR = Path(__file__).parent.resolve().absolute()
EXAMPLE_DATA_DIR = SRC_DIR.parent.resolve() / "example_data"

NUCLEOBASES = ("A", "T", "G", "C")

HEADER = "> Dinosaur DNA"


@lru_cache  # remove this to generate a new sequence upon every iteration
def gen_random_sequence(length: int = 80):
    """Generate a randome DNA sequence of the given length."""
    return "".join([choice(NUCLEOBASES) for _ in range(length)])  # nosec


def write_random_fasta(n_lines: int = 5000000):
    """Write a random fasta file."""

    start_time = time.perf_counter()

    with open(EXAMPLE_DATA_DIR / "big-file.fasta", "w", encoding="utf8") as file:
        file.write(f"{HEADER}\n")

        n_seq_lines = n_lines - 1  # substracting the header
        for _ in range(n_seq_lines):
            dna_sequence = gen_random_sequence(length=80)
            file.write(f"{dna_sequence}\n")

    stop_time = time.perf_counter()
    elapsed_timed = stop_time - start_time
    print(f"Finished generation in {elapsed_timed} seconds.")


if __name__ == "__main__":
    write_random_fasta()
