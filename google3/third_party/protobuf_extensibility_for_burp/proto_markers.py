"""Custom user markers and processing functions."""

import base64
import re

# define the markers used to identify nested protobufs
marker_start = b"$$"
marker_end = marker_start
marker_regex = re.escape(marker_start) + b"(.*?)" + re.escape(marker_end)


# user-definable functions to encode and decode values within markers
def marker_encode(marker):
  """User-definable function to encode protobufs within marker."""
  return base64.b64encode(marker)


def marker_decode(marker):
  """User-definable function to decode protobufs within marker."""
  return base64.b64decode(marker)
