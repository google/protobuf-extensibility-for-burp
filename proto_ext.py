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
"""Burp Protobuf Extension!"""

import os

from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory
from java.io import PrintWriter
from proto_lib import decode_protobuf
from proto_lib import encode_protobuf


# DEV boilerplate
# to output text to console (Stdout/Stderr)
# self.stdout.println("")
#
# write a burp alert message
# self.callbacks.issueAlert("")
#
# throw an exception
# from java.lang import RuntimeException
# raise RuntimeException("")


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
  """The base extension class.

  https://portswigger.net/burp/extender/api/burp/iburpextender.html
  """

  def registerExtenderCallbacks(self, callbacks):
    self.callbacks = callbacks
    self.helpers = callbacks.getHelpers()
    self.stdout = PrintWriter(callbacks.getStdout(), True)
    self.stderr = PrintWriter(callbacks.getStderr(), True)
    callbacks.registerMessageEditorTabFactory(self)
    callbacks.setExtensionName("protobuf manipulation")

    self.stdout.println("Startup!")

  # https://portswigger.net/burp/extender/api/burp/imessageeditortabfactory.html
  def createNewInstance(self, controller, editable):
    return ProtoTab(self, controller, editable)


class ProtoTab(IMessageEditorTab):
  """The implementation of the editor tab (added as a HTTP editor tab).

  https://portswigger.net/burp/extender/api/burp/imessageeditortab.html
  """

  def __init__(self, extender, controller, editable):
    self.extender = extender
    self.editable = editable
    self.txt_input = extender.callbacks.createTextEditor()
    self.txt_input.setEditable(editable)
    self.helpers = extender.helpers
    self.stdout = extender.stdout
    self.stderr = extender.stderr
    self.original_content = None  # copy of the original request/response

  # We only enable the extension on requests/responses with "proto" or
  # "application/octet-stream" in the "content-type" header as there is no
  # standardized protobuf header type!
  def isEnabled(self, content, is_request):

    # fetch the headers
    if is_request:
      req = self.helpers.analyzeRequest(content)
      headers = req.getHeaders()
    else:
      resp = self.helpers.analyzeResponse(content)
      headers = resp.getHeaders()

    # check for "proto" or "application/octet-stream" headers!
    for header in headers:
      if ":" in header:
        header_split = header.split(":")
        if header_split[0].lower() == "content-type":
          value = header_split[1].lower()
          if "proto" in value or "application/octet-stream" in value:
            # show the "Protobuf" tab
            return True

    # no match, don't show the "Protobuf" tab
    return False

  def getTabCaption(self):
    return "Protobuf"

  def getUiComponent(self):
    return self.txt_input.getComponent()

  def isModified(self):
    return self.txt_input.isTextModified()

  def getSelectedData(self):
    return self.txt_input.getSelectedText()

  # extension internal function to get the message
  # body from the HTTP request/response
  def fetchMessageBody(self, content, is_request):
    if is_request:
      req = self.helpers.analyzeRequest(content)
      offset = req.getBodyOffset()
      return content[offset:]
    else:
      resp = self.helpers.analyzeResponse(content)
      offset = resp.getBodyOffset()
      return content[offset:]

  # gets the content of the Protobuf tab and updates the request/response!
  def getMessage(self):

    # don't continue with an empty buffer
    if not self.txt_input.getText().tostring():
      self.original_content = self.helpers.buildHttpMessage(
          self.helpers.analyzeRequest(self.original_content).getHeaders(),
          "",
      )
      return self.original_content

    # get the content of the protobuf tab
    text_input = self.txt_input.getText().tostring()

    # hand off to protoscope to encode back into the http body!
    encode_output = encode_protobuf(text_input)

    self.content = self.helpers.buildHttpMessage(
        self.helpers.analyzeRequest(self.original_content).getHeaders(),
        encode_output,
    )

    return self.content

  # set the contents of the editor tab based on protoc and our own parser
  # protobuf -> decode -> type annotation -> editor tab
  def setMessage(self, content, is_request):

    # `cat tmp | protoc --encode=burp.M0 test.proto | protoc --decode_raw`
    # is not perfectly symeterical, avoid calling --decode_raw more than once
    # to avoid flip-flopping and to avoid changing the user-edited proto again!
    if self.original_content is not None:
      return

    # save a copy of the content so we can use the headers later
    self.original_content = content

    # don't proceed with nothing to decode
    if content is None:
      self.txt_input.setText("")
      return

    # fetch body content from message
    body_content = self.fetchMessageBody(content, is_request)

    # decode using protoscope!
    decoded = decode_protobuf(body_content)

    # set the text box content!
    self.txt_input.setText(decoded)

    # use the existing editable value
    self.txt_input.setEditable(self.editable)
