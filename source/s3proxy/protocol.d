module s3proxy.protocol;

import s3proxy.http : HttpRequest;
import mir.algebraic : nullable, Nullable;
import aws.sigv4 : CanonicalRequest;
import std.socket : Socket;

enum S3Operation {
  info,
  list,
  download,
  upload,
  uploadMultipartStart,
  uploadMultipartFinish,
  uploadMultipart,
  unknown,
}

struct Credential {
  string accessKey;
  string date;
  string region;
  string service;
  string request;
}

struct SignatureHeader {
  string algorithm;
  Credential credential;
  string[] signedHeaders;
  string signature;
}

Nullable!Credential extractCredential(ref HttpRequest req) @safe pure {
  import s3proxy.http : getHeaderOpt;
  import mir.algebraic : optionalMatch;
  import std.algorithm : findSplitAfter, until;
  import std.string : split;
  import std.conv : text;
  import s3proxy.utils : getEnforce, andThen;
  return req.getHeaderOpt!string("authorization").andThen!((string header){
      auto parts = header.findSplitAfter("Credential=")[1].until(',').text().split("/");
      return Credential(parts[0], parts[1], parts[2], parts[3], parts[4]);
    });
}

Nullable!SignatureHeader extractSignatureHeader(ref HttpRequest req) @safe pure nothrow {
  import s3proxy.http : getHeaderOpt;
  import mir.algebraic : optionalMatch;
  import std.algorithm : findSplitAfter, until, findSplit, each, map;
  import std.string : split, strip;
  import std.conv : text;
  import s3proxy.utils : andThen, ifThrown;
  return req.getHeaderOpt!string("authorization").andThen!((string header){
      auto firstSplit = header.findSplit(" ");
      auto sh = SignatureHeader();
      sh.algorithm = firstSplit[0];
      firstSplit[2].split(",").map!(s => s.split("=")).each!((kv){
          switch (strip(kv[0])) {
          case "Credential": {
            auto parts = kv[1].split("/");
            sh.credential = Credential(parts[0], parts[1], parts[2], parts[3], parts[4]);
            break;
          }
          case "SignedHeaders": sh.signedHeaders = kv[1].split(";"); break;
          case "Signature": sh.signature = kv[1]; break;
          default: throw new Exception("Invalid key '"~kv[0]~"' in authorization header");
          }
        });
      return sh;
    }).ifThrown(Nullable!SignatureHeader().init);
}

Nullable!CanonicalRequest extractCanonicalRequest(ref HttpRequest req, Nullable!SignatureHeader signatureHeader) @safe pure nothrow {
  import mir.algebraic : optionalMatch;
  import std.algorithm : each,map;
  import s3proxy.http : parseQueryParams, getHeaderOpt;
  import s3proxy.utils : getEnforce, andThen, ifThrown;
  return signatureHeader.andThen!((SignatureHeader sh) @trusted {
      string[string] headers;
      sh.signedHeaders.each!(h => headers[h] = req.getHeaderOpt!string(h).getEnforce("Expected header "~h));
      auto hash = req.getHeaderOpt!string("x-amz-content-sha256").getEnforce("Expected x-amz-content-sha256 header");
      return CanonicalRequest(cast(string)req.method, cast(string)req.path, req.parseQueryParams, headers, hash);
    }).ifThrown(Nullable!CanonicalRequest.init);
}

struct S3RequestInfo {
  SignatureHeader signatureHeader;
  CanonicalRequest canonicalRequest;
  string datetime;
}

Nullable!S3RequestInfo extractRequestInfo(ref HttpRequest req) @safe pure nothrow {
  import s3proxy.http : getHeaderOpt;
  import mir.algebraic : optionalMatch;
  import s3proxy.utils : getEnforce;
  auto sh = req.extractSignatureHeader;
  auto cr = req.extractCanonicalRequest(sh);
  return optionalMatch!((SignatureHeader sh, CanonicalRequest cr) => S3RequestInfo(sh, cr, req.getHeaderOpt!string("x-amz-date").getEnforce("Expected x-amz-date")))(sh, cr);
}

// TODO: test this one (maybe kill the other??)
auto guessS3Operation(ref S3RequestInfo req) @safe pure {
  import std.algorithm : canFind;

  if (req.canonicalRequest.method == "HEAD") {
    return S3Operation.info;
  } else if (req.canonicalRequest.method == "GET") {
    if (req.canonicalRequest.uri[$-1] == '/')
      return S3Operation.list;
    return S3Operation.download;
  } else if (req.canonicalRequest.method == "PUT") {
    if ("uploadId" in req.canonicalRequest.queryParameters)
      return S3Operation.uploadMultipart;
    else
      return S3Operation.upload;
  } else if (req.canonicalRequest.method == "POST") {
    if (auto u = "uploads" in req.canonicalRequest.queryParameters) {
      if (*u == "" || u is null)
        return S3Operation.uploadMultipartStart;
      return S3Operation.uploadMultipartFinish;
    }
  }
  return S3Operation.unknown;
}

void sendS3Error(Socket socket, Exception e, string resource, string requestId) @safe {
  socket.sendS3Error(500, "InternalError", e.msg, resource, requestId);
}

void sendS3Error(Socket socket, ushort statusCode, string code, string message, string resource, string requestId) @safe {
  import s3proxy.http;
  import std.conv : to;
  import std.format : format;
  string content = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>%s</Code><Message>%s</Message><Resource>%s</Resource><RequestId>%s</RequestId></Error>".format(code, message, resource, requestId);

  socket.sendHttpResponse(statusCode, ["connection":"close","content-type":"application/xml","content-length":content.length.to!string], content);
}

void sendTextError(Socket socket, ushort statusCode, string message) @safe {
  import s3proxy.http;
  import std.conv : to;
  import std.format : format;

  socket.sendHttpResponse(statusCode, ["connection":"close","content-type":"text/plain","content-length":message.length.to!string], message);
}

Nullable!string extractBucket(ref HttpRequest req) @trusted pure nothrow {
  import std.algorithm : splitter;
  import std.range : drop;
  import std.exception : assumeWontThrow;
  import s3proxy.utils : firstOpt;
  return (cast(string)req.path).splitter('/').drop(1).assumeWontThrow.firstOpt;
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
