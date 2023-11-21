import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:strobe/strobe.dart';

void main() {
  final Strobe s = Strobe.initStrobe('custom_hash', Security.bit128);

  final Uint8List message =
      utf8.encode('Hello, Drop a star if you like this repo!');
  s.aD(false, message); // meta = false

  // output length = 16
  // 7ce830010a697657a77b71efff657dd8
  print(hex.encode(s.prf(16)));
}
