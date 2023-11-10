## Strobe
This repository contains an implementation of the [Strobe protocol framework](https://strobe.sourceforge.io/). See [this blogpost](https://www.cryptologie.net/article/416/the-strobe-protocol-framework/) for an explanation of what is the framework.

## Usage

```dart
import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:strobe/strobe.dart';

void main() {
  final Strobe s = Strobe.initStrobe('custom_hash', Security.bit128);

  final List<int> message =
      utf8.encode('Hello, Drop a star if you like this repo!');
  s.aD(false, message); // meta = false

  // output length = 16
  // 7ce830010a697657a77b71efff657dd8
  print(hex.encode(s.prf(16)));
}
```