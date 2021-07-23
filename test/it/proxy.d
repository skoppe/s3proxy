module proxy;

import s3proxy.utils;
import s3proxy.server;
import std.socket : Socket, AddressFamily, SocketType, parseAddress;
import unit_threaded;

@("upload")
@trusted unittest {
  import concurrency.stream : transform, take;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.http;
  import s3proxy.proxy;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyUpload(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      s3Client(port).upload("test-bucket", "my-file", cast(ubyte[])[1,2,3,4,5]);
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
}

@("list")
@trusted unittest {
  import concurrency.stream : transform, take;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.http;
  import s3proxy.proxy;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyList(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      s3Client(port).list("test-bucket", "/", null, null, 100);
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
}

@("download")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.http;
  import s3proxy.proxy;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyDownload(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      return s3Client(port).download("test-bucket", "my-file").responseHeaders["content-length"];
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
  result.value.should == "5";
}

@("info")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.proxy;
  import s3proxy.http;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyDownload(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      return s3Client(port).info("test-bucket", "my-file")["content-length"];
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
  result.value.should == "5";
}

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
[[servers]]
name = "localstack"
endpoint = "http://0.0.0.0:4566"
key = "test"
secret = "test"
[[authentications]]
name = "test"
type = "credentials"
key = "test"
secret = "test"
[[buckets]]
server = "localstack"
name = "test-bucket"
[[buckets.0.access]]
permissions = ["read", "write"]
auth = "test"
`;
  auto config = cast(shared)loadConfig(toml).parseConfig();
  auto api = shared Proxy(config);

  auto runServer = server.transform((socket_t t) shared @trusted {
      nursery.run(just(t).via(pool.getScheduler().schedule()).withStopToken(&api.handle));
    }).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
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
      stopSource.stop();
    });

  nursery.run(runServer);
  whenAll(nursery, writeOne).syncWait(stopSource).assumeOk;
}
