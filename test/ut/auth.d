module auth;

import s3proxy.auth;
import s3proxy.config;
import s3proxy.protocol;
import aws.sigv4 : CanonicalRequest;
import unit_threaded;

S3RequestInfo validListRequest() @safe pure nothrow {
  return S3RequestInfo(SignatureHeader("AWS4-HMAC-SHA256", Credential("test", "20210716", "us-east-1", "s3", "aws4_request"), ["host", "x-amz-content-sha256", "x-amz-date"], "b94e6180c3db76255cd36db1b82b7872b6560e3132128f0982c5d1b96162c59b"),
                       CanonicalRequest("GET", "/test-bucket/", ["delimiter":"/", "prefix":"", "encoding-type":"url", "max-keys":"100", "list-type":"2"], ["host":"0.0.0.0:39239", "x-amz-content-sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date":"20210716T085824Z"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                       "20210716T085824Z"

                       );
}

@("authenticateRequest.list.valid")
pure @safe unittest {
  auto auths = [Authentication([Permission.read, Permission.write], Authenticator(CredentialAuthenticator("auth","test","test")))];

  authenticateRequest(validListRequest, auths).should == true;
}

@("authenticateRequest.list.no-read")
pure @safe unittest {
  auto auths = [Authentication([Permission.write], Authenticator(CredentialAuthenticator("auth","test","test")))];

  authenticateRequest(validListRequest, auths).should == false;
}

@("authenticateRequest.list.wrong-user")
pure @safe unittest {
  auto auths = [Authentication([Permission.write], Authenticator(CredentialAuthenticator("auth","wrong","test")))];

  authenticateRequest(validListRequest, auths).should == false;
}

@("authenticateRequest.list.wrong-pass")
pure @safe unittest {
  auto auths = [Authentication([Permission.write], Authenticator(CredentialAuthenticator("auth","test","wrong")))];

  authenticateRequest(validListRequest, auths).should == false;
}

@("hasPermissionFor")
pure @safe unittest {
  auto writeonly = Authentication([Permission.write]);
  auto readonly = Authentication([Permission.read]);
  auto both = Authentication([Permission.write, Permission.read]);
  writeonly.hasPermissionFor(S3Operation.info).should == false;
  writeonly.hasPermissionFor(S3Operation.list).should == false;
  writeonly.hasPermissionFor(S3Operation.download).should == false;
  writeonly.hasPermissionFor(S3Operation.upload).should == true;
  writeonly.hasPermissionFor(S3Operation.uploadMultipartStart).should == true;
  writeonly.hasPermissionFor(S3Operation.uploadMultipartFinish).should == true;
  writeonly.hasPermissionFor(S3Operation.uploadMultipart).should == true;
  writeonly.hasPermissionFor(S3Operation.unknown).should == false;

  readonly.hasPermissionFor(S3Operation.info).should == true;
  readonly.hasPermissionFor(S3Operation.list).should == true;
  readonly.hasPermissionFor(S3Operation.download).should == true;
  readonly.hasPermissionFor(S3Operation.upload).should == false;
  readonly.hasPermissionFor(S3Operation.uploadMultipartStart).should == false;
  readonly.hasPermissionFor(S3Operation.uploadMultipartFinish).should == false;
  readonly.hasPermissionFor(S3Operation.uploadMultipart).should == false;
  readonly.hasPermissionFor(S3Operation.unknown).should == false;

  both.hasPermissionFor(S3Operation.info).should == true;
  both.hasPermissionFor(S3Operation.list).should == true;
  both.hasPermissionFor(S3Operation.download).should == true;
  both.hasPermissionFor(S3Operation.upload).should == true;
  both.hasPermissionFor(S3Operation.uploadMultipartStart).should == true;
  both.hasPermissionFor(S3Operation.uploadMultipartFinish).should == true;
  both.hasPermissionFor(S3Operation.uploadMultipart).should == true;
  both.hasPermissionFor(S3Operation.unknown).should == false;
}
