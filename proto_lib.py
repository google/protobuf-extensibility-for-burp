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
import tempfile


def decode_protobuf(proto_input):
  """call protoc --decode_raw.

  Args:
    proto_input: data to decode

  Returns:
    - stdout of command
  """

  tmp_file = tempfile.NamedTemporaryFile(delete=False)
  with open(tmp_file.name, "wb") as f:
    f.write(proto_input)
    f.close()
  p = subprocess.Popen(["protoscope", tmp_file.name],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE)
  stdout = p.communicate()[0]
  os.remove(tmp_file.name)

  return stdout


def encode_protobuf(proto_input):
  """call protoc --encode.

  Args:
    proto_input: data to encode

  Returns:
    - stdout of command
  """

  tmp_file = tempfile.NamedTemporaryFile(delete=False)
  with open(tmp_file.name, "wb") as f:
    f.write(proto_input)
    f.close()
  p = subprocess.Popen(["protoscope", "-s", tmp_file.name],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE)
  stdout = p.communicate()[0]
  os.remove(tmp_file.name)

  return stdout
