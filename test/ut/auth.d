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
@safe unittest {
  auto auths = [Access([Permission.read, Permission.write], Authentication(CredentialAuthentication("auth","test","test")))];

  authenticateRequest(validListRequest, auths).should == true;
}

@("authenticateRequest.list.no-read")
@safe unittest {
  auto auths = [Access([Permission.write], Authentication(CredentialAuthentication("auth","test","test")))];

  authenticateRequest(validListRequest, auths).should == false;
}

@("authenticateRequest.list.wrong-user")
@safe unittest {
  auto auths = [Access([Permission.write], Authentication(CredentialAuthentication("auth","wrong","test")))];

  authenticateRequest(validListRequest, auths).should == false;
}

@("authenticateRequest.list.wrong-pass")
@safe unittest {
  auto auths = [Access([Permission.write], Authentication(CredentialAuthentication("auth","test","wrong")))];

  authenticateRequest(validListRequest, auths).should == false;
}

@("hasPermissionFor")
pure @safe unittest {
  auto writeonly = Access([Permission.write]);
  auto readonly = Access([Permission.read]);
  auto both = Access([Permission.write, Permission.read]);
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

@("generateKey")
unittest {
  import std.algorithm : all;
  import s3proxy.utils : getRng;
  auto key = WebIdentityAuthentication("bla", "ev", 10).generateKey(getRng);
  key.prefix.should == "WEBA";
  key.salt[].should.not == WebIdentityAuthentication.WebIdentityKey.salt.init;
  key.expiry[].should.not == WebIdentityAuthentication.WebIdentityKey.expiry.init;
}

@("generateSecret")
unittest {
  auto iden = WebIdentityAuthentication.WebIdentityKey([10,11,12,13,14,15],[120,121,122,124]);
  WebIdentityAuthentication("test","secret").generateSecret(iden).should == "jcFGKJ6pIGZ1KrTzMlI1XOUKwuMFyUuMGlzoTpeavge53nM6/9K7t0jKlTO2";
  WebIdentityAuthentication("test","secret2").generateSecret(iden).should == "8d4CVkfWlTJrN8mFWYnGKgnuEqAZ7jBgqQWYZXIEP05pPsmGRopA3L4kJmU/";
  WebIdentityAuthentication("test2","secret").generateSecret(iden).should == "jcFGKJ6pIGZ1KrTzMlI1XOUKwuMFyUuMGlzoTpeavge53nM6/9K7t0jKlTO2";
}

@("parseKey")
unittest {
  auto key = WebIdentityAuthentication.parseKey("WEBABIFQYDIOB54HS6T4");
  key.salt.should == [10,11,12,13,14,15];
  key.expiry.should == [120,121,122,124];
  WebIdentityAuthentication("test","secret").generateSecret(key).should == "jcFGKJ6pIGZ1KrTzMlI1XOUKwuMFyUuMGlzoTpeavge53nM6/9K7t0jKlTO2";
}

@("generateIdentity")
unittest {
  import s3proxy.utils : getRng;
  auto a = WebIdentityAuthentication("test","secret").generateIdentity(getRng);
  auto b = WebIdentityAuthentication("test","secret").generateIdentity(getRng);
  a.should.not == b;
}

@("WebIdentityKey.toString")
unittest {
  WebIdentityAuthentication.WebIdentityKey([10,11,12,13,14,15],[120,121,122,124]).toString.should == "WEBABIFQYDIOB54HS6T4";
}

