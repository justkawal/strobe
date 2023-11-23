part of strobe;

/// The size of the authentication tag used in AEAD functions
const maclen = 16;

enum Security {
  bit128(128),
  bit256(256);

  final int bit;
  const Security(this.bit);
}

/// STROBEVERSIONTAG = utf8.encode('STROBEv1.0.2');
/// adding domain = [1, (0 ~~> (s.strobeR + 2) & 0xFF), 1, 0, 1, 96]; in front of strobe version tag
/// replacing (s.strobeR + 2) & 0xFF with 0 as a proxy which could be replaced with strobeR in actual usage area.
///
/// length = 18
final STROBEVERSIONTAG = List<int>.from(
    [1, 0, 1, 0, 1, 96, 83, 84, 82, 79, 66, 69, 118, 49, 46, 48, 46, 50],
    growable: false);

class Strobe {
  Strobe._();

  /// KEY inserts a key into the state.
  /// It also provides forward secrecy.
  void key(Uint8List key) {
    operate(false, 'KEY', key, 0, false);
  }

  ///
  /// KEY inserts a key into the state.

  /// PRF provides a hash of length `output_len` of all previous operations
  /// It can also be used to generate random numbers, it is forward secure.
  Uint8List prf(int outputLen) {
    return operate(false, 'PRF', Uint8List(0), outputLen, false);
  }

  /// Send_ENC_unauthenticated is used to encrypt some plaintext
  /// it should be followed by Send_MAC in order to protect its integrity
  /// `meta` is used for encrypted framing data.
  Uint8List sendEncUnauthenticated(bool meta, Uint8List plaintext) {
    return operate(meta, 'send_ENC', plaintext, 0, false);
  }

  /// Recv_ENC_unauthenticated is used to decrypt some received ciphertext
  /// it should be followed by Recv_MAC in order to protect its integrity
  /// `meta` is used for decrypting framing data.
  Uint8List recvEncUnauthenticated(bool meta, Uint8List ciphertext) {
    return operate(meta, 'recv_ENC', ciphertext, 0, false);
  }

  /// AD allows you to authenticate Additional Data
  /// it should be followed by a Send_MAC or Recv_MAC in order to truly work
  void aD(bool meta, List<int> additionalData) {
    operate(meta, 'AD', additionalData, 0, false);
  }

  /// Send_CLR allows you to send data in cleartext
  /// `meta` is used to send framing data
  void sendClr(bool meta, Uint8List cleartext) {
    operate(meta, 'send_CLR', cleartext, 0, false);
  }

  /// Recv_CLR allows you to receive data in cleartext.
  /// `meta` is used to receive framing data
  void recvClr(bool meta, Uint8List cleartext) {
    operate(meta, 'recv_CLR', cleartext, 0, false);
  }

  /// Send_MAC allows you to produce an authentication tag.
  /// `meta` is appropriate for checking the integrity of framing data.
  Uint8List sendMac(bool meta, int outputLength) {
    return operate(meta, 'send_MAC', Uint8List(0), outputLength, false);
  }

  /// Recv_MAC allows you to verify a received authentication tag.
  /// `meta` is appropriate for checking the integrity of framing data.
  bool recvMac(bool meta, Uint8List mac) {
    return operate(meta, 'recv_MAC', mac, 0, false)[0] == 0;
  }

  /// RATCHET allows you to introduce forward secrecy in a protocol.
  void ratchet(int length) {
    operate(false, 'RATCHET', Uint8List(0), length, false);
  }

  /// Send_AEAD allows you to encrypt data and authenticate additional data
  /// It is similar to AES-GCM.
  Uint8List sendAead(Uint8List plaintext, Uint8List ad) {
    List<int> ciphertext = [];
    ciphertext.addAll(sendEncUnauthenticated(false, plaintext));
    aD(false, ad);
    ciphertext.addAll(sendMac(false, maclen));
    return Uint8List.fromList(ciphertext);
  }

  /// Recv_AEAD allows you to decrypt data and authenticate additional data
  /// It is similar to AES-GCM.
  (List<int>, bool) recvAead(Uint8List ciphertext, Uint8List ad) {
    List<int> plaintext = <int>[];
    bool ok = true;

    if (ciphertext.length < maclen) {
      ok = false;
      return (plaintext, ok);
    }

    plaintext = recvEncUnauthenticated(
        false, ciphertext.sublist(0, ciphertext.length - maclen));
    aD(false, ad);
    ok = recvMac(false, ciphertext.sublist(ciphertext.length - maclen));

    return (plaintext, ok);
  }

  ///
  /// Strobe Objects
  ///

  /// Config
  late int duplexRate; // 1600/8 - security/4
  late int strobeR; // duplexRate - 2

  /// Strobe-specific
  late bool initialized; // Used to avoid padding during the first permutation
  late int posBegin; // Start of the current operation (0 := previous block)
  late Role io; // You would define the 'Role' enum as previously mentioned

  // Streaming API
  late int curFlags;

  /// Duplex construction
  /// The actual state
  final List<BigInt> a = List<BigInt>.generate(25, (_) => BigInt.zero);

  /// A pointer into the storage, it also serves as the `pos` variable
  List<int> buf = <int>[];

  /// To-be-XORed (used for optimization purposes)
  List<int> storage = <int>[];

  /// Utility slice used for temporary duplexing operations
  Uint8List tempStateBuf = Uint8List(0);

  /// Clone allows you to clone a Strobe state.
  Strobe clone() {
    final Strobe newStrobe = Strobe._()
      ..duplexRate = duplexRate
      ..strobeR = strobeR
      ..initialized = initialized
      ..posBegin = posBegin
      ..io = io
      ..curFlags = curFlags
      ..a.setAll(0, a)
      ..storage = List<int>.from(storage)
      ..tempStateBuf = Uint8List.fromList(tempStateBuf);
    newStrobe.buf = newStrobe.storage.sublist(0, buf.length);

    return newStrobe;
  }

  /// Serialize allows one to serialize the strobe state to later recover it.
  Uint8List serialize() {
    // Serialized data
    final Uint8List serialized = Uint8List(6 + 25 * 8);

    // Security
    final int security = (1600 ~/ 8 - duplexRate) * 4;
    serialized[0] = (security == 128) ? 0 : 1;

    // Initialized
    serialized[1] = (initialized) ? 1 : 0;

    // I0
    serialized[2] = io.index;

    // curFlags
    serialized[3] = curFlags;

    // posBegin
    serialized[4] = posBegin;

    // pos
    serialized[5] = buf.length;

    // Make sure to XOR what's left to XOR in the storage
    final Uint8List buffer = Uint8List(1600 ~/ 8);
    buffer.setAll(
        0,
        storage.sublist(
            0, buf.length > storage.length ? storage.length : buf.length));
    final List<BigInt> state = List<BigInt>.from(a);
    xorState(state, buffer);

    // Serialize the 'state' List<BigInt> into 'serialized' Uint8List
    int currentIndex = 6;
    for (int i = 0; i < 25; i++) {
      final Uint8List uint8List =
          bigIntToUint8List(state[i], 8); // Convert BigInt to Uint8List
      serialized.setAll(currentIndex, uint8List);
      currentIndex += 8;
    }

    return serialized;
  }

  /// Function to convert BigInt to Uint8List of a specific length
  Uint8List bigIntToUint8List(BigInt number, int length) {
    final Uint8List uint8List = Uint8List(length);
    for (int i = 0; i < length; i++) {
      uint8List[i] = number.toUnsigned(8).toInt();
      number >>= 8;
    }
    return uint8List;
  }

  /// Recover state allows one to re-create a strobe state from a serialized state.
  static Strobe recoverState(Uint8List serialized) {
    if (serialized.length != 6 + 25 * 8) {
      throw Exception('strobe: cannot recover state of invalid length');
    }

    final int security = (serialized[0] > 1) ? 256 : 128;

    final Strobe s = Strobe._()..duplexRate = 1600 ~/ 8 - security ~/ 4;
    s
      ..strobeR = s.duplexRate - 2
      ..storage = Uint8List(s.duplexRate)
      ..tempStateBuf = Uint8List(s.duplexRate)
      ..initialized = (serialized[1] == 1);
    if (serialized[2] > 3) {
      throw Exception('strobe: cannot recover state with invalid role');
    }
    s
      ..io = Role.values[serialized[2]]
      ..curFlags = serialized[3]
      ..posBegin = serialized[4];

    final int pos = serialized[5];
    s.buf = List<int>.from(s.storage.sublist(0, pos));

    int currentIndex = 6;
    for (int i = 0; i < 25; i++) {
      final value =
          ByteData.sublistView(serialized, currentIndex, currentIndex + 8)
              .getUint64(0, Endian.little);
      s.a[i] = BigInt.from(value);
      currentIndex += 8;
    }

    return s;
  }

  ///
  /// Flags
  final Map<String, int> _operationMap = {
    'AD': Flag.flagA.bit,
    'KEY': Flag.flagA.bit | Flag.flagC.bit,
    'PRF': Flag.flagI.bit | Flag.flagA.bit | Flag.flagC.bit,
    'send_CLR': Flag.flagA.bit | Flag.flagT.bit,
    'recv_CLR': Flag.flagI.bit | Flag.flagA.bit | Flag.flagT.bit,
    'send_ENC': Flag.flagA.bit | Flag.flagC.bit | Flag.flagT.bit,
    'recv_ENC':
        Flag.flagI.bit | Flag.flagA.bit | Flag.flagC.bit | Flag.flagT.bit,
    'send_MAC': Flag.flagC.bit | Flag.flagT.bit,
    'recv_MAC': Flag.flagI.bit | Flag.flagC.bit | Flag.flagT.bit,
    'RATCHET': Flag.flagC.bit,
  };

  /// this only works for 8-byte alligned buffers
  void xorState(List<BigInt> state, List<int> buf) {
    final int n = buf.length ~/ 8;
    for (int i = 0; i < n; i++) {
      BigInt a = bytesToUint64(buf.sublist(i * 8, (i + 1) * 8));
      state[i] ^= a;
    }
  }

  BigInt bytesToUint64(List<int> bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result += (BigInt.from(bytes[i]) << (i * 8));
    }
    return result;
  }

  /// this only works for 8-byte alligned buffers
  void outState(List<BigInt> state, Uint8List b) {
    final n = b.length ~/ 8;
    for (int i = 0; i < n; i++) {
      Uint8List bytes = uint64ToBytes(state[i]);
      b.setAll(i * 8, bytes.toList());
    }
  }

  Uint8List uint64ToBytes(BigInt value) {
    final Uint8List bytes = Uint8List(8);
    for (int i = 0; i < 8; i++) {
      bytes[i] = (value & BigInt.from(0xFF)).toUnsigned(8).toInt();
      value >>= 8;
    }
    return bytes;
  }

  /// since the golang implementation does not absorb
  /// things in the state 'right away' (sometimes just
  /// wait for the buffer to fill) we need a function
  /// to properly print the state even when the state
  /// is in this 'temporary' state.
  String debugPrintState() {
    // Copy _storage into buf
    final Uint8List buffer = Uint8List(1600 ~/ 8);
    buffer.setAll(
        0,
        storage.sublist(
            0, buf.length > storage.length ? storage.length : buf.length));

    // Copy _state into state
    final List<BigInt> state = List<BigInt>.from(a);

    // XOR
    xorState(state, buffer);

    // Print
    outState(state, buffer);
    return hex.encode(buffer);
  }

  ///
  /// Core functions
  ///
  /// InitStrobe allows you to initialize a new strobe instance with a customization string (that can be empty) and a security target (either 128 or 256).
  static Strobe initStrobe(String customizationString, Security security) {
    final Strobe s = Strobe._()..duplexRate = 1600 ~/ 8 - (security.bit) ~/ 4;

    s
      ..strobeR = s.duplexRate - 2
      ..storage = Uint8List(s.duplexRate)
      ..tempStateBuf = Uint8List(s.duplexRate)
      ..io = Role.iNone
      ..initialized = false;

    final Uint8List domain = Uint8List(18);
    domain.setAll(0, STROBEVERSIONTAG);
    domain[1] = (s.strobeR + 2) & 0xFF;

    s
      ..buf = <int>[]
      ..duplex(domain, false, false, true)
      ..initialized = true
      ..operate(true, 'AD', utf8.encode(customizationString), 0, false);

    return s;
  }

  /// runF: applies the STROBE's + cSHAKE's padding and the Keccak permutation
  void runF() {
    if (initialized) {
      // If initialized, apply Strobe padding
      if (buf.length > strobeR) {
        throw Exception('strobe: buffer is never supposed to reach strobeR');
      }
      buf.add(posBegin);
      storage[buf.length - 1] = posBegin;
      buf.add(0x04);
      storage[buf.length - 1] = 0x04;
      buf.addAll(Uint8List(duplexRate - buf.length));
      buf[duplexRate - 1] ^= 0x80;
      storage[duplexRate - 1] ^= 0x80;
      xorState(a, buf);
    } else if (buf.isNotEmpty) {
      // If not initialized, pad with zeros for xorState to work
      // rate = [0--end_of_buffer/zeroStart---duplexRate]
      buf = List<int>.from(storage.sublist(0, duplexRate));
      for (int i = buf.length; i < duplexRate; i++) {
        buf[i] = 0;
      }
      xorState(a, buf);
    }

    // Run the permutation
    keccakF1600(a, 24);

    // Reset the buffer and set posBegin to 0
    // (meaning that the current operation started on a previous block)
    buf.clear();
    posBegin = 0;
  }

  /// duplex: the duplex call
  void duplex(Uint8List data, bool cbefore, bool cafter, bool forceF) {
    int currentIndex = 0;

    // Process data block by block
    while (currentIndex < data.length) {
      int todo = strobeR - buf.length;
      if (todo > data.length - currentIndex) {
        todo = data.length - currentIndex;
      }

      if (cbefore) {
        outState(a, tempStateBuf);
        for (int idx = currentIndex; idx < currentIndex + todo; idx++) {
          data[idx] ^= tempStateBuf[buf.length + idx - currentIndex];
        }
      }

      // Buffer what's to be XOR'ed (we XOR once during runF)
      buf.addAll(data.sublist(currentIndex, currentIndex + todo));
      storage.setAll(0, buf);

      if (cafter) {
        outState(a, tempStateBuf);
        for (int idx = currentIndex; idx < currentIndex + todo; idx++) {
          data[idx] ^= tempStateBuf[buf.length - todo + idx - currentIndex];
        }
      }

      currentIndex += todo;

      // If the duplex is full, it's time to XOR + pad + permute.
      if (buf.length == strobeR) {
        runF();
      }
    }

    // Sometimes we want the next operation to start on a new block
    if (forceF && buf.isNotEmpty) {
      runF();
    }
  }

  /// Operate runs an operation (see OperationMap for a list of operations).
  /// For operations that only require a length, provide the length via the
  /// length argument with an empty slice []byte{}. For other operations provide
  /// a zero length.
  /// Result is always retrieved through the return value. For boolean results,
  /// check that the first index is 0 for true, 1 for false.
  Uint8List operate(
      bool meta, String operation, List<int> dataConst, int length, bool more) {
    // Operation is valid?
    late int flags;
    if (_operationMap.containsKey(operation)) {
      flags = _operationMap[operation]!;
    } else {
      throw Exception('Not a valid operation');
    }

    // Operation is meta?
    if (meta) {
      flags |= Flag.flagM.bit;
    }

    late final Uint8List data;

    if (((flags & (Flag.flagI.bit | Flag.flagT.bit)) !=
            (Flag.flagI.bit | Flag.flagT.bit)) &&
        ((flags & (Flag.flagI.bit | Flag.flagA.bit)) != Flag.flagA.bit)) {
      if (length == 0) {
        throw Exception('A length should be set for this operation.');
      }
      data = Uint8List(length);
    } else {
      if (length != 0) {
        throw Exception(
            'Output length must be zero except for PRF, send_MAC, and RATCHET operations.');
      }
      data = Uint8List.fromList(dataConst);
    }

    if (more) {
      if (flags != curFlags) {
        throw Exception('Flag should be the same when streaming operations.');
      }
    } else {
      beginOp(flags);
      curFlags = flags;
    }

    final bool cAfter =
        (flags & (Flag.flagC.bit | Flag.flagI.bit | Flag.flagT.bit)) ==
            (Flag.flagC.bit | Flag.flagT.bit);
    final bool cBefore = (flags & Flag.flagC.bit != 0) && (!cAfter);

    duplex(data, cBefore, cAfter, false);

    if ((flags & (Flag.flagI.bit | Flag.flagA.bit)) ==
        (Flag.flagI.bit | Flag.flagA.bit)) {
      return data;
    } else if ((flags & (Flag.flagI.bit | Flag.flagT.bit)) == Flag.flagT.bit) {
      return data;
    } else if ((flags & (Flag.flagI.bit | Flag.flagA.bit | Flag.flagT.bit)) ==
        (Flag.flagI.bit | Flag.flagT.bit)) {
      if (more) {
        throw Exception(
            'Not supposed to check a MAC with the \'more\' streaming option');
      }
      int failures = 0;
      for (int dataByte in data) {
        failures |= dataByte;
      }
      final result = Uint8List(1);
      result[0] = failures; // 0 if correct, 1 if not
      return result; // 0 if correct, 1 if not
    }

    return Uint8List(0);
  }

  /// beginOp: starts an operation
  void beginOp(int flags) {
    if (flags & Flag.flagT.bit != 0) {
      if (io.index == Role.iNone.index) {
        io = Role.values[flags & Flag.flagI.bit];
      }
      flags ^= Flag.values[io.index].index;
    }

    final int oldBegin = posBegin;
    posBegin = (buf.length + 1).toUnsigned(8); // s.pos + 1
    final bool forceF = (flags & (Flag.flagC.bit | Flag.flagK.bit) != 0);
    duplex(Uint8List.fromList([oldBegin, flags & 0xFF]), false, false, forceF);
  }
}

enum Flag {
  flagI(1),
  flagA(2),
  flagC(4),
  flagT(8),
  flagM(16),
  flagK(32);

  final int bit;
  const Flag(this.bit);
}

enum Role {
  iInitiator, // set if we send the first transport message
  iResponder, // set if we receive the first transport message
  iNone // starting value
}
