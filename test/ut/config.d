module config;

import s3proxy.config;
import s3proxy.auth;
import unit_threaded;
import mir.algebraic;

@("servers")
@safe unittest {
  string content = `[[server]]
name = "digitalocean"
endpoint = "asdf"
key = "asdf"
secret = "asdf"
`;
  auto config = content.loadConfig();
  config.servers.length.should == 1;
}

@("authentications")
@safe unittest {
  string content =`[[authentication]]
name = "ci-upload"
type = "credentials"
key = "asdf"
secret = "s"
`;

  auto config = content.loadConfig();
  config.authentications.length.should == 1;
}

@("authentications")
@safe unittest {
  string content =`[[bucket]]
server = "digitalocean"
name = "sil-artifacts"

[[bucket.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"

[[bucket.0.access]]
permissions = ["read"]
auth = "sil-download"`;

  auto config = content.loadConfig();
  config.buckets.length.should == 1;
  config.buckets[0].access.length.should == 2;
  config.buckets[0].access[0].permissions.length.should == 2;
  config.buckets[0].access[0].permissions[0].should == Permission.read;
}

@("parse.server.valid")
@safe unittest {
  string content = `[[server]]
name = "digitalocean"
endpoint = "asdf"
key = "asdf"
secret = "asdf"
[[bucket]]
server = "digitalocean"
name = "sil-artifacts"`;
  auto config = content.loadConfig().parseConfig();
  config.buckets.length.should == 1;
  config.buckets[0].server.endpoint.should == "asdf";
}

@("parse.server.notfound")
@safe unittest {
  string content = `[[server]]
name = "digitalocean2"
[[bucket]]
server = "digitalocean"`;
  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, cannot find server 'digitalocean'");
}

@("parse.server.duplicate")
@safe unittest {
  string content = `[[server]]
name = "digitalocean"
[[server]]
name = "digitalocean"
[[bucket]]
server = "digitalocean"`;
  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, duplicate servers 'digitalocean'");
}

@("authentications.valid")
@safe unittest {
  string content =`[[server]]
name = "digitalocean"
[[authentication]]
type = "credentials"
name = "ci-upload"
key = "key"
[[bucket]]
server = "digitalocean"
name = "sil-artifacts"
[[bucket.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  auto config = content.loadConfig().parseConfig();
  config.buckets.length.should == 1;
  config.buckets[0].access.length.should == 1;
  config.buckets[0].access[0].permissions.should == [Permission.read, Permission.write];
  auto auth = config.buckets[0].access[0].authentication.trustedGet!CredentialAuthentication;
  auth.key.should == "key";
}

@("authentications.no-type")
@safe unittest {
  string content =`[[server]]
name = "digitalocean"
[[authentication]]
name = "ci-upload"
[[bucket]]
server = "digitalocean"
name = "sil-artifacts"
[[bucket.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, authentication 'ci-upload' missing type field");
}

@("authentications.notfound")
@safe unittest {
  string content =`[[server]]
name = "digitalocean"
[[bucket]]
server = "digitalocean"
name = "sil-artifacts"
[[bucket.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, cannot find authentication 'ci-upload'");
}

@("authentications.duplicate")
@safe unittest {
  string content =`[[server]]
name = "digitalocean"
[[authentication]]
name = "ci-upload"
[[authentication]]
name = "ci-upload"
[[bucket]]
server = "digitalocean"
name = "sil-artifacts"
[[bucket.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, duplicate authentication 'ci-upload'");
}

@("oauth")
@safe unittest {
  string content =`[[oauth]]
endpoint = "https://git.example.com/oauth/token/info"
scopes = ["api"]
auth = "ci-upload"
[[authentication]]
type = "web"
name = "ci-upload"
secret = "secret"
expires = 3600`;

  auto config = content.loadConfig().parseConfig();
  config.oauthProviders.length.should == 1;
  config.oauthProviders[0].tryMatch!((OAuthAuthenticationProvider oauth) @safe {
      oauth.endpoint.toString.should == "https://git.example.com/oauth/token/info";
      oauth.scopes.should == ["api"];
      oauth.auth.tryMatch!((WebIdentityAuthentication auth){
          auth.name.should == "ci-upload";
          auth.secret.should == "secret";
          auth.expires.should == 3600;
        });
    });
}
