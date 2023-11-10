## Strobe
This repository contains an implementation of the [Strobe protocol framework](https://strobe.sourceforge.io/). See [this blogpost](https://www.cryptologie.net/article/416/the-strobe-protocol-framework/) for an explanation of what is the framework.

## Usage

```dart
import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:strobe/strobe.dart';

void main() {
  final Strobe s =
      Strobe.initStrobe('AnyStrobeHash', Security.bit128);

  final List<int> message = utf8.encode('Hello sir, How\'s your day going?');
  s.aD(false, message); // meta = false

  // output length = 16 
  // c96ff4e5cb10c20168af74e25b3cd4d3
  print(hex.encode(s.prf(16)));
}
```