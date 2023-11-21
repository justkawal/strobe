import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:strobe/strobe.dart';
import 'package:test/test.dart';

void main() {
  final Uint8List message = utf8.encode("hello, how are you good sir?");
  test('Strobe Clone Test', () {
    var s1 = Strobe.initStrobe("myHash", Security.bit128);
    var s2 = s1.clone();

    s1.operate(false, "AD", message, 0, false);
    var out1 = hex.encode(s1.prf(32));
    expect(
        out1,
        equals(
            "c694b4b202f35cfe52d0da39532b282eaf9ad8ed824e46251386050bc4237b32"));

    s2.operate(false, "AD", message, 0, false);
    var out2 = hex.encode(s2.prf(32));
    expect(
        out2,
        equals(
            "c694b4b202f35cfe52d0da39532b282eaf9ad8ed824e46251386050bc4237b32"));

    expect(out1, equals(out2));

    s1.operate(false, "send_ENC", message, 0, false);
    out1 = hex.encode(s1.prf(32));

    expect(
        out1,
        equals(
            "e3d05246384f976385193be34ccf018c70e2ba04fdbf2ec47ace4b172414e902"));

    s2.operate(false, "send_ENC", message, 0, false);
    out2 = hex.encode(s2.prf(32));
    expect(
        out2,
        equals(
            "e3d05246384f976385193be34ccf018c70e2ba04fdbf2ec47ace4b172414e902"));
  });

  test('Strobe Stream Test', () {
    var message1 = "hello";
    var message2 = "how are you good sir?";
    var fullmessage = message1 + message2;

    var s1 = Strobe.initStrobe("myHash", Security.bit128);
    var s2 = s1.clone();

    s1.operate(
        false, "AD", Uint8List.fromList(fullmessage.codeUnits), 0, false);
    var out1 = hex.encode(s1.prf(32));

    expect(
        out1,
        equals(
            "131fd4a1d84e4b10a73fd2b5da26720c632088d48efff7d3f131d89fc447a4d4"));

    s2.operate(false, "AD", Uint8List.fromList(message1.codeUnits), 0, false);
    s2.operate(false, "AD", Uint8List.fromList(message2.codeUnits), 0, true);
    var out2 = hex.encode(s2.prf(32));

    expect(
        out2,
        equals(
            "131fd4a1d84e4b10a73fd2b5da26720c632088d48efff7d3f131d89fc447a4d4"));
  });
  test('Strobe Stream Test 2', () {
    var s = Strobe.initStrobe(
        "custom string number 2, that's a pretty long string", Security.bit128);
    var key = utf8.encode("0101010100100101010101010101001001");
    s.operate(false, "KEY", key, 0, false);
    s.operate(false, "KEY", key, 0, true);
    var message = utf8.encode("hello, how are you good sir? ????");
    s.operate(false, "AD", message, 0, false);
    s.operate(false, "AD", message, 0, true);
    s.operate(false, "AD", message, 0, false);
    final out = s.debugPrintState();
    if (out !=
        "5117b46c2d842655c1be2a69f64f16aaaad2c0050fe2ac5446afe44345a9b10d044c8b3ec8005a9e362c0a431ab5c4d8228c2f890ae56ad3fef4404aa6cc76704b503d627553ae9635d329cdfa86ed29ec0dd79787ff3fcefdee7463c053ef3b4a4fa7c8eb89a6372df2c4ccfc7469d7447bd19a67940642334706e5ff6b1ef58514e55c6b5c6921c58eb7cb5c57978c92c42e598926fcfdcd9705fb948ed6fe9027c65fb0659c98a9c9668d523dfa2b27bde76224944503b686901c989fedac34994dd16daedf00") {
      fail("this is not working");
    }
  });

  test('Strobe Recovery Test', () {
    var s = Strobe.initStrobe(
        "custom string number 2, that's a pretty long string", Security.bit128);
    var key = utf8.encode("0101010100100101010101010101001001");
    s.operate(false, "KEY", key, 0, false);
    s.operate(false, "KEY", key, 0, true);

    // Serialize and clone
    var cloned = s.clone();
    var serialized = s.serialize();

    // Recover
    var recovered = Strobe.recoverState(serialized);

    // Compare recovered and cloned
    recovered.operate(false, "send_ENC", message, 0, false);
    var out1 = hex.encode(recovered.prf(32));
    expect(
        out1,
        equals(
            "dd84363bb2cbd3f89b01125e9a0a38e5b16f88c6de3a4a07d8955b8eeb728896"));

    cloned.operate(false, "send_ENC", message, 0, false);
    var out2 = hex.encode(cloned.prf(32));
    expect(
        out2,
        equals(
            "dd84363bb2cbd3f89b01125e9a0a38e5b16f88c6de3a4a07d8955b8eeb728896"));

    recovered.operate(false, "send_MAC", Uint8List(16), 16, false);
    out1 = hex.encode(recovered.prf(32));

    expect(
        out1,
        equals(
            "b067e64a593609656bb08baad05b32c0e1d22f3fab96b658429bb92c5119ce1d"));
    cloned.operate(false, "send_MAC", Uint8List(16), 16, false);
    out2 = hex.encode(cloned.prf(32));

    expect(
        out2,
        equals(
            "b067e64a593609656bb08baad05b32c0e1d22f3fab96b658429bb92c5119ce1d"));
  });
}
