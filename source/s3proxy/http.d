module s3proxy.http;

struct Header
{
  const(char)[] name;
  const(char)[] value;
}

template sliceUntil(alias fun) {
  auto sliceUntil(Range)(Range range) nothrow {
    import std.algorithm : countUntil;
    try {
      auto cnt = range[].countUntil!fun;
      if (cnt == -1)
        return range;
      else
        return range[0..cnt];
    } catch (Exception e) {
      assert(0);
    }
  }
}

struct HttpRequest
{
  @safe pure nothrow @nogc:
  void onMethod(const(char)[] method) { this.method = method; }
  void onUri(const(char)[] uri) {
    this.uri = uri;
    this.path = uri.sliceUntil!(c => c == '?');
    this.query = uri[this.path.length .. $];
  }
  int onVersion(const(char)[] ver)
  {
    import httparsed : parseHttpVersion;
    minorVer = parseHttpVersion(ver);
    return minorVer >= 0 ? 0 : minorVer;
  }
  void onHeader(const(char)[] name, const(char)[] value) {
    this.m_headers[m_headersLength].name = name;
    this.m_headers[m_headersLength++].value = value;
  }
  void onStatus(int status) { this.status = status; }
  void onStatusMsg(const(char)[] statusMsg) { this.statusMsg = statusMsg; }

  const(char)[] method;
  const(char)[] uri;
  const(char)[] path;
  const(char)[] query;
  int minorVer;
  int status;
  const(char)[] statusMsg;

  private {
    Header[32] m_headers;
    size_t m_headersLength;
  }

  Header[] headers() return { return m_headers[0..m_headersLength]; }

  private {
    ubyte[] buffer;
    uint lastPos;
  }

  ubyte[] rest() {
    return buffer[lastPos..$];
  }
}

auto httpRequestParser() @safe {
  import httparsed;
  return initParser!HttpRequest();
}

import std.socket : Socket;
HttpRequest parseHttpRequest(Socket socket, ubyte[] buffer) @safe {
  import std.socket;
  import httparsed;
  auto reqParser = initParser!HttpRequest();

  int res;
  uint lastPos = 0;
  size_t start = 0;
  ptrdiff_t read;
 retry:
  read = socket.receive(buffer[start..$]);
  if (read == 0)
    throw new Exception("Connection closed");
  if (read == Socket.ERROR) {
    if (wouldHaveBlocked)
      throw new Exception("Timeout");
    throw new Exception("socket error: "~lastSocketError);
  }
  res = reqParser.parseRequest(buffer[0..start+read], lastPos);
  if (res == -ParserError.partial) {
    // reallocate buffer, reread
    start = start + read;
    buffer.length = buffer.length*2;
    goto retry;
  }
  auto msg = reqParser.msg;
  msg.buffer = buffer[0..start+read];
  msg.lastPos = lastPos;

  return msg;
}

HttpRequest parseHttpRequest(ubyte[] buffer) @safe pure {
  import httparsed;
  auto reqParser = initParser!HttpRequest();
  uint lastPos;
  auto res = reqParser.parseRequest(buffer, lastPos);
  assert(res >= 1);
  auto msg = reqParser.msg;
  msg.buffer = buffer;
  msg.lastPos = lastPos;

  return msg;
}

HttpRequest parseHttpRequest(string buffer) @trusted pure {
  return parseHttpRequest(cast(ubyte[])buffer);
}

import mir.algebraic : Nullable;
Nullable!T getHeaderOpt(T)(ref HttpRequest req, string header) nothrow {
  import std.algorithm : find;
  import std.string : toLower;
  import s3proxy.utils : firstOpt, ifThrown;
  import std.conv : to;
  import mir.algebraic : optionalMatch;

  return req.headers.find!(h => h.name.toLower == header).firstOpt.optionalMatch!((Header h) => h.value.to!T).ifThrown(Nullable!T.init);
}

Nullable!size_t contentLength(ref HttpRequest req) @safe {
  return req.getHeaderOpt!(size_t)("content-length");
}

import mir.algebraic : Nullable;
Nullable!size_t decodedContentLength(ref HttpRequest req) @safe {
  return req.getHeaderOpt!(size_t)("x-amz-decoded-content-length");
}

auto contentRange(ref HttpRequest req, Socket socket, ubyte[] buffer, size_t contentLength) @safe {
  struct ContentRange {
    ubyte[] start;
    ubyte[] buffer;
    Socket socket;
    size_t contentLength;
    this(ref HttpRequest req, Socket socket, ubyte[] buffer, size_t contentLength) @safe {
      start = req.rest();
      this.socket = socket;
      this.buffer = buffer;
      this.contentLength = contentLength;
    }
    bool empty() @safe {
      return contentLength == 0;
    }
    ubyte[] front() @safe {
      return start;
    }
    void popFront() @safe {
      import std.algorithm : min;
      contentLength -= start.length;
      if (contentLength > 0) {
        auto read = socket.receive(buffer[0..min(buffer.length, contentLength)]);
        start = buffer[0..read];
      }
    }
  }
  return ContentRange(req, socket, buffer, contentLength);
}

string[string] parseQueryParams(ref HttpRequest req) @safe pure {
  import std.uri : decodeComponent;
  import std.algorithm : splitter, each;
  import std.string : split;
  string[string] params;
  if (req.query.length == 0)
    return params;
  req.query[1..$].splitter('&').each!((kv){
      auto parts = kv.split('=');
      if (parts.length == 1)
        params[decodeComponent(parts[0])] = "";
      else
        params[decodeComponent(parts[0])] = decodeComponent(parts[1]);
    });
  return params;
}

void sendHttpResponse(Range)(Socket socket, ushort code, string[string] responseHeaders, Range content) {
  import std.algorithm : map, joiner;
  import std.range : only;
  import std.conv : text, to;
  socket.send("HTTP/1.1 "~code.to!string~" \r\n");
  socket.send(responseHeaders.byKeyValue.map!(kv => only(kv.key, ": ", kv.value).joiner()).joiner("\r\n").text());
  socket.send("\r\n\r\n");
  foreach(chunk; content) {
    socket.send(chunk);
  }
}
