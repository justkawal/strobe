import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:strobe/strobe.dart';

void main() {
  final Strobe s =
      Strobe.initStrobe('AnyStrobeHash', Security.bit128); // 128-bit security
  final List<int> message = utf8.encode('Hello sir, How\'s your day going?');
  s.aD(false, message); // meta = false

  // output length = 16 // c96ff4e5cb10c20168af74e25b3cd4d3
  print(hex.encode(s.prf(16)));
}
