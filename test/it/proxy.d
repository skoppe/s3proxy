module proxy;

import s3proxy.utils;
import s3proxy.server;
import std.socket : Socket, AddressFamily, SocketType, parseAddress;
import unit_threaded;

@("operations")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.stoptoken;
  import concurrency.operations : via, then, whenAll, withStopToken;
  import concurrency.thread;
  import concurrency;
  import concurrency.nursery;
  import s3proxy.proxy;
  import s3proxy.http;
  import s3proxy.server;
  import s3proxy.config;
  import std.file : readText;
  import concurrency.stoptoken;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);
  auto pool = cast(shared)stdTaskPool(8);
  auto stopSource = new shared StopSource();
  auto nursery = new shared Nursery();

  auto toml = `
[[server]]
name = "localstack"
endpoint = "http://0.0.0.0:4566"
key = "test"
secret = "test"
[[authentication]]
name = "test"
type = "credentials"
key = "test"
secret = "test"
[[bucket]]
server = "localstack"
name = "test-bucket"
[[bucket.0.access]]
permissions = ["read", "write"]
auth = "test"
`;
  auto config = cast(shared)loadConfig(toml).parseConfig();
  auto api = shared Proxy(config);

  auto runServer = server.transform((socket_t t) shared @trusted {
      nursery.run(just(t).via(pool.getScheduler().schedule()).withStopToken(&api.handle));
    }).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      s3Client(4566).createBucket("test-bucket");

      s3Client(port,"wrong","test")
        .list("test-bucket", "/", null, null, 100)
        .shouldThrowWithMessage("AccessDenied: Access denied");

      s3Client(port,"test","wrong")
        .list("test-bucket", "/", null, null, 100)
        .shouldThrowWithMessage("AccessDenied: Access denied");

      s3Client(port,"test","test")
        .list("test-bucket", "/", null, null, 100)
        .shouldNotThrow();

      s3Client(port,"test","test")
        .list("unknown-bucket", "/", null, null, 100)
        .shouldThrowWithMessage("NoSuchBucket: No such bucket: unknown-bucket");

      s3Client(port).upload("test-bucket", "my-file", cast(ubyte[])[1,2,3,4,5]);
      s3Client(port).list("test-bucket", "/", null, null, 100);
      s3Client(port).download("test-bucket", "my-file").responseHeaders["content-length"].should == "5";
      s3Client(port).info("test-bucket", "my-file")["content-length"].should == "5";
      stopSource.stop();
    });

  nursery.run(runServer);
  whenAll(nursery, writeOne).syncWait(stopSource).assumeOk;
}

@("health")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.stoptoken;
  import concurrency.operations : via, then, whenAll, withStopToken;
  import concurrency.thread;
  import concurrency;
  import concurrency.nursery;
  import s3proxy.proxy;
  import s3proxy.http;
  import s3proxy.server;
  import s3proxy.config;
  import std.file : readText;
  import concurrency.stoptoken;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);
  auto pool = cast(shared)stdTaskPool(8);
  auto stopSource = new shared StopSource();
  auto nursery = new shared Nursery();

  auto toml = `
[[server]]
name = "localstack"
endpoint = "http://0.0.0.0:4566"
key = "test"
secret = "test"
[[authentication]]
name = "test"
type = "credentials"
key = "test"
secret = "test"
[[bucket]]
server = "localstack"
name = "test-bucket"
[[bucket.0.access]]
permissions = ["read", "write"]
auth = "test"
`;
  auto config = cast(shared)loadConfig(toml).parseConfig();
  auto api = shared Proxy(config);

  auto readOne = server.transform((socket_t t) shared @trusted {
      nursery.run(just(t).via(pool.getScheduler().schedule()).withStopToken(&api.handle));
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      import requests;
      import std.conv : to;
      auto req = Request();
      return req.execute("GET", "http://0.0.0.0:"~port.to!string~"/health").code;
    });

  nursery.run(readOne);
  auto result = whenAll(nursery, writeOne).syncWait(stopSource);
  result.assumeOk;
  result.value.should == 204;
}
