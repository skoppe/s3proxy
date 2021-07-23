# S3 Proxy

Forward S3 requests to one or more s3 storage providers and inject authentication and encryption.

# Production

The proxy is stateless and requires only a config file.

## Config

Put a `s3proxy.toml` in the same folder and run the binary.

### Example config

```toml
[[servers]]
name = "digitalocean"
endpoint = "https://s3provider.com"
key = "key"
secret = "secret"
region = "us-east-1"

[[authentications]]
name = "upload"
type = "credentials"
key = "key"
secret = "secret"

[[authentications]]
name = "client"
type = "credentials"
key = "key"
secret = "secret"

[[buckets]]
server = "digitalocean"
name = "artifacts"

[[buckets.0.access]]
permissions = ["write"]
auth = "upload"

[[buckets.0.access]]
permissions = ["read"]
auth = "client"
```

# Development

## Testing

Run `dub test` for the unittests.

Run `docker-compose up -d` and `dub -c it -b unittest` for the integration tests. And `docker-compose down` to stop it again.

# Beta at the moment

Come back in a few weeks

# Our sponsors

[<img src="https://raw.githubusercontent.com/libmir/mir-algorithm/master/images/symmetry.png" height="80" />](http://symmetryinvestments.com/)
