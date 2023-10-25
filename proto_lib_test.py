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
"""Unit test for proto_lib.py."""

# Note: Burp uses Python 2.x with Jython. Be sure to keep this file 2.x
# compatible to allow for realistic testing.

import unittest
import proto_lib

class TestProtoLib(unittest.TestCase):

  def testEncodeAndDecode(self):
    # test both the encode and decode functions
    test_input = b'1: 43\n2: {42: {"my even more awesome awesome proto"}}\n'
    stdout = proto_lib.encode_protobuf(test_input)
    decoded = proto_lib.decode_protobuf(stdout)
    self.assertEqual(decoded, test_input)

if __name__ == '__main__':
  unittest.main()
