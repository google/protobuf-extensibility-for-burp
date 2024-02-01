# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Helper library for ProtoExt.py."""

import os
import subprocess


def decode_protobuf(proto_input):
  """call protoscope.

  Args:
    proto_input: data to decode

  Returns:
    - stdout of command
  """

  p = subprocess.Popen(["protoscope"],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE)
  stdout = p.communicate(input=proto_input)[0]

  return stdout


def encode_protobuf(proto_input):
  """call protoscope -s.

  Args:
    proto_input: data to encode

  Returns:
    - stdout of command
  """

  p = subprocess.Popen(["protoscope", "-s"],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE)
  stdout = p.communicate(input=proto_input)[0]

  return stdout
