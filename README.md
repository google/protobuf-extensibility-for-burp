# Protobuf Extensibility For Burp

The objective of this Burp Suite extension is to make protobuf manipulation
 easier in Burp Suite by allowing users to modify protos in requests and
 responses.

For alternatives to this extension please consider the following extensions:

- https://github.com/dillonfranke/protoburp
- https://github.com/nccgroup/blackboxprotobuf/tree/master/burp
- https://github.com/federicodotta/protobuf-decoder

The following resources were helpful to us during development of this extension:

- https://protobuf.dev/overview/
- https://www.swiftforensics.com/2020/03/parsing-unknown-protobufs-with-python.html
- https://downrightnifty.me/blog/2022/12/26/hacking-google-home.html

This extension supports either:

1. Wire protobufs in the request body (when the `Content-Type` header contains
 the case-insensitive string `application/octet-stream` or `proto`). **OR**

2. Base64-encoded protobufs anywhere within the request body, marked using the
 start and end markers `$$`. Both the markers and encoding can be changed by
 editing the `proto_markers.py` file.

Markers can also be used with the
 [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)
 extension to support scenarios which require additional layers of encoding.
 Hackvertor must be loaded after this extension to perform encoding in the
 correct order.

# Installation

1) Install [protoscope](https://github.com/protocolbuffers/protoscope/tree/main)
 and add it to your PATH before starting Burp Suite!

2) If you have not already done so, download and install Jython in Burp Suite:\
https://portswigger.net/burp/documentation/desktop/extensions/installing-extensions#installing-jython-or-jruby

3) Download this repo and load the `proto_ext.py` file as a Python Burp Suite
 extension.

Note: This was tested in a linux environment with Burp Suite Professional
 v2023.10.2.2. OSX should work, but has not been tested. Adding Windows support
 should only require updating the system calls in proto_lib.py.

# Test

Using Python 2.7, run the unit tests using:

```
python2 proto_lib_test.py
```

# Origin

This project was originally created during an internship with the Google
 Security Team by Issac Valenzuela with support from Sam Erb, Zak Bennett and
 Collin El-Hossari.