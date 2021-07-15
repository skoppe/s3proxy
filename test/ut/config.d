module config;

import s3proxy.config;
import unit_threaded;

@("servers")
@safe unittest {
  string content = `[[servers]]
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
  string content =`[[authentications]]
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
  string content =`[[buckets]]
server = "digitalocean"
name = "sil-artifacts"

[[buckets.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"

[[buckets.0.access]]
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
  string content = `[[servers]]
name = "digitalocean"
endpoint = "asdf"
key = "asdf"
secret = "asdf"
[[buckets]]
server = "digitalocean"
name = "sil-artifacts"`;
  auto config = content.loadConfig().parseConfig();
  config.buckets.length.should == 1;
  config.buckets[0].server.endpoint.should == "asdf";
}

@("parse.server.notfound")
@safe unittest {
  string content = `[[servers]]
name = "digitalocean2"
[[buckets]]
server = "digitalocean"`;
  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, cannot find server 'digitalocean'");
}

@("parse.server.duplicate")
@safe unittest {
  string content = `[[servers]]
name = "digitalocean"
[[servers]]
name = "digitalocean"
[[buckets]]
server = "digitalocean"`;
  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, duplicate servers 'digitalocean'");
}

@("authentications.valid")
@safe unittest {
  string content =`[[servers]]
name = "digitalocean"
[[authentications]]
type = "credentials"
name = "ci-upload"
key = "key"
[[buckets]]
server = "digitalocean"
name = "sil-artifacts"
[[buckets.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  auto config = content.loadConfig().parseConfig();
  config.buckets.length.should == 1;
  config.buckets[0].auth.length.should == 1;
  config.buckets[0].auth[0].permissions.should == [Permission.read, Permission.write];
  auto auth = config.buckets[0].auth[0].authenticator.trustedGet!CredentialAuthenticator;
  auth.key.should == "key";
}

@("authentications.no-type")
@safe unittest {
  string content =`[[servers]]
name = "digitalocean"
[[authentications]]
name = "ci-upload"
[[buckets]]
server = "digitalocean"
name = "sil-artifacts"
[[buckets.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, authentication 'ci-upload' missing type field");
}

@("authentications.notfound")
@safe unittest {
  string content =`[[servers]]
name = "digitalocean"
[[buckets]]
server = "digitalocean"
name = "sil-artifacts"
[[buckets.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, cannot find authentication 'ci-upload'");
}

@("authentications.duplicate")
@safe unittest {
  string content =`[[servers]]
name = "digitalocean"
[[authentications]]
name = "ci-upload"
[[authentications]]
name = "ci-upload"
[[buckets]]
server = "digitalocean"
name = "sil-artifacts"
[[buckets.0.access]]
permissions = ["read", "write"]
auth = "ci-upload"`;

  content.loadConfig().parseConfig().shouldThrowWithMessage("Config error, duplicate authentication 'ci-upload'");
}
