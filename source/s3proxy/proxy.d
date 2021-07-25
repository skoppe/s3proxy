module s3proxy.proxy;

import aws.s3;
import aws.aws : chunkedContent;
import s3proxy.http;
import s3proxy.config;
import std.socket;
import s3proxy.protocol;
import s3proxy.utils : ignoreException;
import std.algorithm : find, map, count, sum, joiner;
import std.range : front, only;
import std.string : toLower;
import concurrency.stoptoken : StopToken;
import std.conv : to;

struct Proxy {
  Config config;
  this(shared Config config) @trusted nothrow shared {
    this.config = config;
  }
  this(Config config) @trusted nothrow shared {
    this.config = cast(shared)config;
  }
  Nullable!(Bucket) lookupBucket(string bucketName) @trusted nothrow shared {
    import std.algorithm : map;
    import s3proxy.utils : firstOpt;
    return config.buckets.find!(b => b.name == bucketName).map!(b => cast()b).firstOpt;
  }
  void endpoint(ref HttpRequest req, Socket socket) @trusted shared nothrow {
    import s3proxy.protocol;
    import s3proxy.auth;

    auto bucketName = req.extractBucket();
    if (bucketName.isNull) {
      socket.sendError(501, "NotImplemented", "List buckets not implemented", cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    auto bucket = lookupBucket(bucketName.get);
    if (bucket.isNull) {
      socket.sendError(404, "NoSuchBucket", "No such bucket: "~bucketName.get, cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    auto info = extractRequestInfo(req);
    if (info.isNull) {
      socket.sendError(400, "InvalidArgument", "Invalid request", cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    if (!authenticateRequest(info.get, bucket.get.auth)) {
      socket.sendError(401, "AccessDenied", "Access denied", cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    auto s3 = bucket.get.server.getClient;
    auto operation = info.get.guessS3Operation();
    try {
      final switch (operation) with(S3Operation) {
        case info: return s3.proxyInfo(req, socket);
        case list: return s3.proxyList(req, socket);
        case upload: return s3.proxyUpload(req, socket);
        case download: return s3.proxyDownload(req, socket);
        case uploadMultipartStart:
        case uploadMultipartFinish:
        case uploadMultipart:
        case unknown:
          break;
        }
    } catch (Exception e) {
      // TODO: log it;
      return;
    }
    socket.sendError(501, "NotImplemented", "Operation not implemented", cast(string)req.path, "0123456789").ignoreException;
  }
  void handle(StopToken stopToken, socket_t t) @trusted shared {
    auto socket = new Socket(t, AddressFamily.INET);
    scope(exit)
      socket.close();
    ubyte[512] scopedBuffer;
    auto req = parseHttpRequest(socket, scopedBuffer[]);
    if (req.path == "/health")
      socket.sendHttpResponse(204, ["connection": "close", "content-length": "0"]);
    else
      endpoint(req, socket);
  }
}

void proxyInfo(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  string[string] headers, params = req.parseQueryParams;

  auto resp = (cast()s3).doRequest("HEAD", cast(string)req.path, params, headers);
  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders["transfer-encoding"] = "chunked";

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange.chunkedContent(512*1024));
}

void proxyList(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  string[string] headers;
  string[string] params = req.parseQueryParams;

  auto resp = (cast()s3).doRequest("GET", cast(string)req.path, params, headers);
  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders["transfer-encoding"] = "chunked";

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange.chunkedContent(512*1024));
}

void proxyUpload(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  import requests : Response;
  import s3proxy.utils : getEnforce;
  Response forwardUpload(Range)(Range content, size_t contentLength) {
    string[string] headers, params;
    string[] additional;
    return (cast()s3).doUpload!(typeof(content))("PUT", cast(string)req.path, params, headers, additional, content, contentLength, 512*1024);
  }
  size_t rawContentLength = req.contentLength.getEnforce("Missing Content-Length");
  ubyte[64] buffer;
  Response resp;

  auto rawContent = contentRange(req, socket, buffer[], rawContentLength);
  auto contentLength = req.decodedContentLength;

  if (contentLength.isNull) {
    resp = forwardUpload(rawContent, rawContentLength);
  } else {
    ubyte[] uploadBuffer = new ubyte[512*1024];
    auto content = rawContent.joiner.decodeChunkedUpload(uploadBuffer).map!(c => c.data);
    resp = forwardUpload(content, contentLength.get);
  }

  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders["transfer-encoding"] = "chunked";

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange.chunkedContent(512*1024));
}

void proxyDownload(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  string[string] headers;
  string[string] params = req.parseQueryParams;

  auto resp = (cast()s3).doRequest("GET", cast(string)req.path, params, headers);

  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders["transfer-encoding"] = "chunked";

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange.chunkedContent(512*1024));
}

S3 getClient(Server server) nothrow @safe {
  import aws.credentials;
  auto creds = new StaticAWSCredentials(server.key, server.secret);
  auto region = server.region ? server.region : "aws-global";
  return new S3(server.endpoint, server.region, creds);
}
