module s3proxy.proxy;

import aws.s3;
import aws.aws : chunkedContent;
import s3proxy.http;
import s3proxy.config;
import s3proxy.jwt;
import std.socket;
import s3proxy.protocol;
import s3proxy.utils : ignoreException;
import std.algorithm : find, map, count, sum, joiner;
import std.range : front, only;
import std.string : toLower;
import concurrency.stoptoken : StopToken;
import std.conv : to;
import std.experimental.logger;

struct Proxy {
  Config config;
  JWKSCache jwksCache;
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
      socket.sendS3Error(501, "NotImplemented", "List buckets not implemented", cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    auto bucket = lookupBucket(bucketName.get);
    if (bucket.isNull) {
      socket.sendS3Error(404, "NoSuchBucket", "No such bucket: "~bucketName.get, cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    auto info = extractRequestInfo(req);
    if (info.isNull) {
      socket.sendS3Error(400, "InvalidArgument", "Invalid request", cast(string)req.path, "0123456789").ignoreException;
      return;
    }

    if (!authenticateRequest(info.get, bucket.get.access)) {
      socket.sendS3Error(401, "AccessDenied", "Access denied", cast(string)req.path, "0123456789").ignoreException;
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
      error(e).ignoreException;
      return;
    }
    socket.sendS3Error(501, "NotImplemented", "Operation not implemented", cast(string)req.path, "0123456789").ignoreException;
  }
  void handle(StopToken stopToken, socket_t t) @trusted shared {
    auto socket = new Socket(t, AddressFamily.INET);
    scope(exit)
      socket.close();
    ubyte[512] scopedBuffer;
    auto req = parseHttpRequest(socket, scopedBuffer[]);
    trace(req);
    if (req.path == "/health")
      socket.sendHttpResponse(204, ["connection": "close", "content-length": "0"]);
    else if (req.path == "/auth")
      generateCredentials(config, jwksCache, req, socket);
    else
      endpoint(req, socket);
  }
}

void generateCredentials(ref shared Config config, ref shared JWKSCache jwksCache, ref HttpRequest req, Socket socket) @trusted nothrow {
  import asdf;
  import s3proxy.utils : ignoreException;
  try {
    string msg = generateCredentials(cast(Config)config, jwksCache, req.parseQueryParams()).serializeToJson();
    socket.sendHttpResponse(200, ["content-type": "application/json", "connection": "close", "content-length": msg.length.to!string ], msg);
  } catch (Exception e) {
    socket.sendTextError(401, e.msg).ignoreException();
  }
}

auto generateCredentials(ref Config config, ref shared JWKSCache jwksCache, string[string] params) @safe {
  auto token = "token" in params;
  if (token is null) {
    throw new Exception("missing token");
  }
  if (auto provider = "provider" in params) {
    // this is an oauth request
  } else {
    return generateOIDCCredentials(config, jwksCache, *token);
  }
  throw new Exception("invalid request");
}

struct OIDCProviderJWTItem {
  import s3proxy.auth : OIDCAuthenticationProvider;
  OIDCAuthenticationProvider provider;
  JWT jwt;
}

auto generateOIDCCredentials(JWKSCache)(ref Config config, ref JWKSCache jwksCache, string token) @trusted {
  import std.algorithm : filter;
  import s3proxy.utils : firstEnforce;
  RawJWT raw = decodeRawJwt(token);
  string issuer = raw.payload["iss"].str;
  auto item = config.oidcProviders
    .filter!(p => p.issuer == issuer)
    .map!((provider){
          JWKS keys = jwksCache.get(issuer);
          JWT jwt = raw.validateRawJwtSignature(keys).validateJwt();
          return OIDCProviderJWTItem(provider, jwt);
      })
    .filter!((item){
        if (item.provider.scopes.length == 0)
          return true;
        return item.jwt.checkScopes(item.provider.scopes);
      })
    .firstEnforce("invalid token");
  return item.provider.auth.generateIdentity;
}

void proxyInfo(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  string[string] headers, params = req.parseQueryParams;

  auto resp = (cast()s3).doRequest("HEAD", cast(string)req.path, params, headers);
  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders.remove("content-encoding");

  socket.sendHttpResponse(resp.code, responseHeaders);
}

void proxyList(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  string[string] headers;
  string[string] params = req.parseQueryParams;

  auto resp = (cast()s3).doRequest("GET", cast(string)req.path, params, headers);
  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders["transfer-encoding"] = "chunked";
  responseHeaders.remove("content-encoding");

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange.chunkedContent(512*1024));
}

void proxyUpload(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  import requests : Response;
  import s3proxy.utils : getEnforce, orElse;
  enum size_t chunkSize = 32*1024;
  Response forwardUpload(Range)(Range content, size_t contentLength, string contentType) {
    string[string] headers = ["content-type": contentType];
    string[string] params;
    string[] additional;
    return (cast()s3).doUpload!(typeof(content))("PUT", cast(string)req.path, params, headers, additional, content, contentLength, chunkSize);
  }
  size_t rawContentLength = req.contentLength.getEnforce("Missing Content-Length");
  ubyte[64] buffer;
  Response resp;

  auto rawContent = contentRange(req, socket, buffer[], rawContentLength);
  auto contentLength = req.decodedContentLength;
  auto contentType = req.getHeaderOpt!string("content-type").orElse("application/octet-stream");

  if (contentLength.isNull) {
    resp = forwardUpload(rawContent, rawContentLength, contentType);
  } else {
    ubyte[] uploadBuffer = new ubyte[chunkSize];
    ubyte[] rebuffered = new ubyte[chunkSize];
    auto content = rawContent.joiner.decodeChunkedUpload(uploadBuffer).map!(c => c.data).rebuffer(rebuffered);

    resp = forwardUpload(content, contentLength.get, contentType);
  }

  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders["transfer-encoding"] = "chunked";
  responseHeaders.remove("content-encoding");

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange.chunkedContent(512*1024));
}

void proxyDownload(S3 s3, ref HttpRequest req, Socket socket) @trusted {
  string[string] headers;
  string[string] params = req.parseQueryParams;

  auto resp = (cast()s3).doRequest("GET", cast(string)req.path, params, headers);

  auto responseHeaders = resp.responseHeaders;
  responseHeaders["connection"] = "close";
  responseHeaders.remove("content-encoding");

  socket.sendHttpResponse(resp.code, responseHeaders, resp.receiveAsRange);
}

S3 getClient(Server server) nothrow @safe {
  import aws.credentials;
  auto creds = new StaticAWSCredentials(server.key, server.secret);
  auto region = server.region ? server.region : "aws-global";
  return new S3(server.endpoint, server.region, creds);
}
