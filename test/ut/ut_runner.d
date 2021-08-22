
import unit_threaded;

int main(string[] args)
{
  return args.runTests!("protocol",
                        "http",
                        "config",
                        "auth",
                        "server",
                        "jwt",
                        "jwk",
                        "webidentity",
                        "crypto"
                        );
}
