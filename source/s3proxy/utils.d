module s3proxy.utils;

import mir.algebraic : Nullable, Algebraic;
import aws.s3 : S3;

auto firstOpt(Range)(Range range) @trusted nothrow {
  import std.range;
  import std.exception : assumeWontThrow;
  if (range.empty)
    return Nullable!(ElementType!Range).init;
  return Nullable!(ElementType!Range)(range.front.assumeWontThrow);
}

auto firstEnforce(Range)(Range range, string msg) @trusted {
  import std.range;
  if (range.empty)
    throw new Exception(msg);
  return range.front;
}

auto ifThrown(L, P)(lazy L main, P second) nothrow {
  import std.traits : isCallable;
  try { return main(); } catch (Exception e) {
    static if (isCallable!P)
      return second(e);
    else
      return second;
  }
}

auto ignoreException(L)(lazy L block) {
  try return block(); catch (Exception e) {}
}

struct RandomSocket {
  import std.socket : socket_t;
  socket_t handle;
  ushort port;
}

RandomSocket openRandomSocket() @trusted {
  import s3proxy.server;
  import std.socket;
  import std.conv : to;
  version (Windows)
    import core.sys.windows.winsock2;
  else
    import core.sys.posix.sys.socket;
  auto sock = openListeningSocket("0.0.0.0", 0);
  sockaddr_in sin;
  socklen_t nameLen = cast(socklen_t) sin.sizeof;
  if (-1 == getsockname(sock.trustedGet, cast(sockaddr*)&sin, &nameLen))
    throw new SocketOSException("Unable to obtain local socket address");
  return RandomSocket(sock.trustedGet, ntohs(sin.sin_port));
}

S3 localstack() {
  return s3Client(4566);
}

S3 s3Client(ushort port, string key = "test", string secret = "test") {
  import aws.credentials;
  import std.conv : to;
  auto creds = new StaticAWSCredentials(key, secret);

  auto region = "us-east-1";
  auto endpoint = "http://0.0.0.0:"~port.to!string;
  return new S3(endpoint,region,creds);
}

auto getEnforce(T)(T t, string msg) if (is(T == Algebraic!(typeof(null), P), P)) {
  import mir.algebraic : optionalMatch, match;
  static if (is(T == Algebraic!(typeof(null), P), P)) {
    P onError() { throw new Exception(msg); }
    return t.match!((P p)=>p, onError)();
  }
}

template andThen(alias fun) {
  import mir.algebraic : optionalMatch, match;
  auto andThen(T)(T t) {
    return t.optionalMatch!(fun);
  }
}

auto orElse(T, L)(T t, lazy L value) {
  import mir.algebraic : match;
  return t.match!((typeof(null))=>value,(ref t)=>t);
}

auto getRng() {
  import std.random : Mt19937;
  alias RNG = Mt19937;
  static RNG* rng;
  if (rng is null) {
    rng = new Mt19937();
    import std.random : unpredictableSeed;
    rng.seed(unpredictableSeed);
  }
  return rng;
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
