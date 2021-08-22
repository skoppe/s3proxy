module s3proxy.webidentity;

auto dequeue(Range, T)(ref Range range, lazy T def) {
  import std.range : empty, front, popFront;
  if (range.empty)
    return def;
  auto r = range.front;
  range.popFront;
  return r;
}

static immutable char[32] keyChars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','2','3','4','5','6','7'];

ubyte keyCharToByte(char k) @safe pure nothrow @nogc {
  if ((k - 'A') >= 0 && (k - 'A') < 26)
    return cast(ubyte)(k - 'A');
  return cast(ubyte)(k - '2' + 26);
}

struct KeyEncoder(Range) {
  private Range range;
  ubyte[8] buffer;
  size_t pos;
  this(Range range) {
    this.range = range;
    encodeIntoBuffer();
  }
  private void encodeIntoBuffer() {
    ubyte def = 0;
    ubyte a = range.dequeue(def);
    ubyte b = range.dequeue(def);
    ubyte c = range.dequeue(def);
    ubyte d = range.dequeue(def);
    ubyte e = range.dequeue(def);
    buffer[0] = a >> 3; // 5 from a
    buffer[1] = (a << 2) & 0x1F | (b >> 6); // 3 from a and 2 from b
    buffer[2] = (b >> 1) & 0x1F; // 5 from b
    buffer[3] = (b << 4) & 0x1F | (c >> 4); // 1 from b and 4 from c
    buffer[4] = (c << 1) & 0x1F | (d >> 7); // 4 from c and 1 from d
    buffer[5] = (d >> 2) & 0x1F; // 5 from d
    buffer[6] = (d << 3) & 0x1F | (e >> 5); // 2 from d and 3 from e
    buffer[7] = e & 0x1F; // 5 from e
    pos = 0;
  }
  bool empty() {
    return pos == 8;
  }
  void popFront() {
    import std.range : empty;
    if (pos == 7 && !range.empty)
      encodeIntoBuffer();
    else
      pos++;
  }
  char front() {
    return keyChars[buffer[pos]];
  }
}

auto keyEncoder(Range)(Range r) {
  return KeyEncoder!Range(r);
}

struct KeyDecoder(Range) {
  private Range range;
  ubyte[8] buffer;
  size_t pos;
  this(Range range) @safe {
    this.range = range;
    encodeIntoBuffer();
  }
  private void encodeIntoBuffer() @safe {
    ubyte def = 0;
    buffer[0] = range.dequeue(def).keyCharToByte;
    buffer[1] = range.dequeue(def).keyCharToByte;
    buffer[2] = range.dequeue(def).keyCharToByte;
    buffer[3] = range.dequeue(def).keyCharToByte;
    buffer[4] = range.dequeue(def).keyCharToByte;
    buffer[5] = range.dequeue(def).keyCharToByte;
    buffer[6] = range.dequeue(def).keyCharToByte;
    buffer[7] = range.dequeue(def).keyCharToByte;
    buffer[0] = ((buffer[0] << 3) & 0xff) | (buffer[1] >> 2);
    buffer[1] = ((buffer[1] << 6) & 0xff) | ((buffer[2] << 1) & 0xff) | (buffer[3] >> 4);
    buffer[2] = ((buffer[3] << 4) & 0xff) | (buffer[4] >> 1);
    buffer[3] = ((buffer[4] << 7) & 0xff) | ((buffer[5] << 2) & 0xff) | (buffer[6] >> 3);
    buffer[4] = ((buffer[6] << 5) & 0xff) | buffer[7];
    pos = 0;
  }
  bool empty() @safe const {
    return pos == 5;
  }
  void popFront() @safe {
    import std.range : empty;
    if (pos == 4 && !range.empty)
      encodeIntoBuffer();
    else
      pos++;
  }
  ubyte front() @safe const {
    return buffer[pos];
  }
}

auto keyDecoder(Range)(Range r) {
  return KeyDecoder!Range(r);
}

