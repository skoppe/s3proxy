module s3proxy.chunk;

struct Chunk {
  ubyte[] buffer;
  size_t length;
  size_t extensionStart;
  size_t dataStart;
  const(char)[] extension() @safe scope return pure {
    return cast(const(char)[])buffer[extensionStart .. dataStart-2];
  }
  ubyte[] data() @safe pure return scope {
    return buffer[dataStart .. dataStart+length];
  }
}

auto readChunkIntoBuffer(Range)(ref Range r, ref ubyte[] buffer, size_t expectedExtensionSize = 85) {
  import std.algorithm : until, copy, map;
  import std.conv : to;
  import std.range : popFront, take, front;
  import std.array : array;
  import std.range : refRange;
  import std.format : formattedRead;
  auto range = refRange(&r);
  size_t extensionStart = 0, dataStart = 0;
  size_t length;
  while(true) {
    buffer[extensionStart++] = range.front();
    range.popFront();
    if (range.front == ';') {
      (cast(char[])buffer[0..extensionStart]).formattedRead("%x", length);
      dataStart = extensionStart;
      buffer[dataStart++] = ';';
      range.popFront();
      if (length+expectedExtensionSize+extensionStart > buffer.length)
        buffer.length = length+expectedExtensionSize+extensionStart;
      // decode extension
      while(true) {
        buffer[dataStart++] = range.front();
        range.popFront();
        if (dataStart > buffer.length)
          buffer.length = length+(dataStart*2);
        if (range.front == '\r') {
          buffer[dataStart++] = '\r';
          buffer[dataStart++] = '\n';
          range.popFront();
          range.popFront();
          break;
        }
      }
      break;
    } else if (range.front == '\r') {
      (cast(char[])buffer[0..extensionStart]).formattedRead("%x", length);
      dataStart = extensionStart;
      buffer[dataStart++] = '\r';
      buffer[dataStart++] = '\n';
      range.popFront();
      range.popFront();
      break;
    }
  }
  if (length+dataStart+2 > buffer.length) {
    buffer.length = length+dataStart+2;
  }
  for(size_t idx = 0; idx < length; idx++) {
    buffer[dataStart+idx] = range.front();
    range.popFront();
  }
  buffer[dataStart+length] = '\r';
  buffer[dataStart+length+1] = '\n';
  range.popFront();
  range.popFront();
  return Chunk(buffer, length, extensionStart, dataStart);
}

auto decodeChunkedUpload(Range)(Range range, ref ubyte[] buffer) {
  struct Decoded {
    ubyte[] buffer;
    Range range;
    Chunk chunk;
    this(Range range, ubyte[] buffer) {
      this.range = range;
      this.buffer = buffer;
      chunk = readChunkIntoBuffer(this.range, this.buffer);
    }
    bool empty() {
      return chunk.buffer.length == 0;
    }
    Chunk front() {
      return chunk;
    }
    void popFront() {
      if (chunk.data.length == 0)
        chunk = Chunk.init;
      else
        chunk = readChunkIntoBuffer(this.range, this.buffer);
    }
  }
  return Decoded(range, buffer);
}

auto rebuffer(Range)(Range range, ubyte[] buffer) {
  import std.range;
  import std.algorithm : min, copy;
  struct Rebuffer {
    Range range;
    ubyte[] leftOver;
    ubyte[] buffer;
    size_t pos;
    this(Range range, ubyte[] buffer) {
      this.range = range;
      this.buffer = buffer;
      if (!this.range.empty) {
        leftOver = this.range.front;
        popFront();
      }
    }
    bool empty() {
      return pos == 0 && leftOver.length == 0 && range.empty;
    }
    auto front() {
      return buffer[0..pos];
    }
    auto popFront() {
      pos = 0;
      while (true) {
        if (leftOver.length > 0) {
          size_t copyLength = min(leftOver.length, buffer.length-pos);
          copy(leftOver[0..copyLength], buffer[pos..$]);
          pos += copyLength;
          leftOver = leftOver[copyLength..$];
          if (leftOver.length > 0 || pos == buffer.length)
            return;
        }
        if (range.empty)
          return;
        range.popFront();
        if (range.empty)
          return;
        leftOver = range.front();
      }
    }
  }
  return Rebuffer(range, buffer);
}
