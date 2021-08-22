module protocol;

import unit_threaded;
import s3proxy.protocol;

@("guessS3Operation")
pure @safe unittest {
  import aws.sigv4 : CanonicalRequest;
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("HEAD"));
    req.guessS3Operation().should == S3Operation.info;
  }
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("GET", "/"));
    req.guessS3Operation().should == S3Operation.list;
  }
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("GET", "/file"));
    req.guessS3Operation().should == S3Operation.download;
  }
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("PUT"));
    req.guessS3Operation().should == S3Operation.upload;
  }
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("PUT", null, ["uploadId":""]));
    req.guessS3Operation().should == S3Operation.uploadMultipart;
  }
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("POST", null, ["uploads":""]));
    req.guessS3Operation().should == S3Operation.uploadMultipartStart;
  }
  {
    auto req = S3RequestInfo(SignatureHeader(), CanonicalRequest("POST", null, ["uploads":"1234"]));
    req.guessS3Operation().should == S3Operation.uploadMultipartFinish;
  }
}

enum testRequest = cast(ubyte[])"GET /test-bucket/?delimiter=%2F&prefix=&encoding-type=url&max-keys=100&list-type=2 HTTP/1.1\r\nUser-Agent: dlang-requests\r\nx-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\nAccept-Encoding: gzip,deflate\r\nhost: 0.0.0.0:39239\r\nx-amz-date: 20210716T085824Z\r\nConnection: Keep-Alive\r\nauthorization: AWS4-HMAC-SHA256 Credential=test/20210716/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=b94e6180c3db76255cd36db1b82b7872b6560e3132128f0982c5d1b96162c59b\r\n\r\n";

@("extractSignatureHeader")
pure @safe unittest {
  import s3proxy.http : parseHttpRequest;
  auto request = testRequest.parseHttpRequest();

  request.extractSignatureHeader.get.should == SignatureHeader("AWS4-HMAC-SHA256", Credential("test", "20210716", "us-east-1", "s3", "aws4_request"), ["host", "x-amz-content-sha256", "x-amz-date"], "b94e6180c3db76255cd36db1b82b7872b6560e3132128f0982c5d1b96162c59b");
}

enum testRequestNoSpace = cast(ubyte[])"GET /test-bucket/?delimiter=%2F&prefix=&encoding-type=url&max-keys=100&list-type=2 HTTP/1.1\r\nUser-Agent: dlang-requests\r\nx-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\nAccept-Encoding: gzip,deflate\r\nhost: 0.0.0.0:39239\r\nx-amz-date: 20210716T085824Z\r\nConnection: Keep-Alive\r\nauthorization: AWS4-HMAC-SHA256 Credential=test/20210716/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=b94e6180c3db76255cd36db1b82b7872b6560e3132128f0982c5d1b96162c59b\r\n\r\n";

@("extractSignatureHeader.no-space")
pure @safe unittest {
  import s3proxy.http : parseHttpRequest;
  auto request = testRequestNoSpace.parseHttpRequest();

  request.extractSignatureHeader.get.should == SignatureHeader("AWS4-HMAC-SHA256", Credential("test", "20210716", "us-east-1", "s3", "aws4_request"), ["host", "x-amz-content-sha256", "x-amz-date"], "b94e6180c3db76255cd36db1b82b7872b6560e3132128f0982c5d1b96162c59b");
}
@("extractCanonicalRequest")
pure @safe unittest {
  import aws.sigv4 : CanonicalRequest;
  import s3proxy.http : parseHttpRequest;
  auto request = testRequest.parseHttpRequest();

  auto sh = request.extractSignatureHeader;
  auto cr = request.extractCanonicalRequest(sh);
  cr.get.should == CanonicalRequest("GET", "/test-bucket/", ["delimiter":"/", "prefix":"", "encoding-type":"url", "max-keys":"100", "list-type":"2"], ["host":"0.0.0.0:39239", "x-amz-content-sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date":"20210716T085824Z"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

@("extractBucket")
pure @safe unittest {
  import s3proxy.http : parseHttpRequest;
  auto request = testRequest.parseHttpRequest();
  request.extractBucket.should == "test-bucket";
}
