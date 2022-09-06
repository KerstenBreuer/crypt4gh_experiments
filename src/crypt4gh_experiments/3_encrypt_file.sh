#!/bin/bash

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

cd /workspace/src

EXAMPLE_DATA_DIR="${PWD}/../example_data/"

START_TIME=$SECONDS

cat "${EXAMPLE_DATA_DIR}/big-file.fasta" | \
    crypt4gh encrypt \
        --sk "${EXAMPLE_DATA_DIR}/sender.sec" \
        --recipient_pk "${EXAMPLE_DATA_DIR}/receiver.pub" \
        > "${EXAMPLE_DATA_DIR}/big-file.fasta.c4gh"

TIME_ELAPSED=$(( SECONDS - START_TIME ))
echo "Encrypted in ${TIME_ELAPSED} seconds."
