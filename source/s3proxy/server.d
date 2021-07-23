module s3proxy.server;

public import std.socket : socket_t;
import concurrency.stoptoken : StopToken, onStop;
import arsd.cgi : Cgi;

auto listenServer(string host, ushort port) @safe {
    return listenServer(openListeningSocket(host,port).trustedGet);
}

auto listenServer(socket_t sock) @safe {
    import concurrency.stream : CollectDelegate, fromStreamOp;
    import core.sys.windows.windows;
    import core.sys.posix.unistd;
    import core.sys.posix.sys.socket;
    import core.sys.posix.sys.wait;
    import core.stdc.stdio : fprintf, stderr;
    import core.sys.posix.sys.select;
    import core.sys.posix.netinet.tcp;
    import core.stdc.errno;
    import core.stdc.stdlib : exit;
    import std.algorithm : max;
    import core.sys.posix.netinet.in_;
    import std.conv : to;

    version (linux) import core.sys.linux.sys.eventfd;

    alias DG = CollectDelegate!(socket_t);
    static struct ServerStreamOp(Receiver) {
        socket_t sock;
        DG dg;
        Receiver receiver;
        @disable this(ref return scope typeof(this) rhs);
        @disable this(this);
        void start() @trusted nothrow {
            auto stopToken = receiver.getStopToken();
            // on linux use an eventfd and have the stoptoken trigger it when stop is requested
            // on windows we while loop and check token every once in a while
            scope (exit)
                closeSocket(sock);
            version (linux) {
                shared int stopfd = eventfd(0, EFD_CLOEXEC);
                scope (exit)
                    close(stopfd);

                auto cb = stopToken.onStop(() shared @trusted {
                        ulong b = 1;
                        write(stopfd, &b, typeof(b).sizeof);
                    });
                scope (exit)
                    cb.dispose();
            }

            while (!stopToken.isStopRequested) {
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(sock, &read_fds);
                version (linux) {
                    FD_SET(stopfd, &read_fds);
                } else {
                    timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 10000;
                }
            retry:
                version (linux) {
                    const ret = select(max(sock, stopfd) + 1, &read_fds, null, null, null);
                } else {
                    const ret = select(cast(int) (sock + 1), &read_fds, null, null, &tv);
                }
                if (ret == 0) {
                    continue;
                } else if (ret == -1) {
                    version (Windows) {
                        const err = WSAGetLastError();
                        if (err == WSAEINTR)
                            continue;
                        else
                            receiver.setError(new Exception("select "~err.to!string));

                    } else {
                        if (errno == EINTR || errno == EAGAIN) {
                            goto retry;
                        } else {
                            import core.stdc.string : strerror;
                            import core.stdc.string : strlen;
                            auto s = strerror(errno);
                            auto errString = s[0 .. s.strlen].idup;
                            receiver.setError(new Exception("select "~errString));
                        }
                    }
                    return;
                }
                version (linux) {
                    if (FD_ISSET(stopfd, &read_fds)) {
                        break;
                    }
                }
                sockaddr addr;
                version (Windows) {
                    int i = cast(int) addr.sizeof;
                } else {
                    uint i = addr.sizeof;
                }
                socket_t connection = cast(socket_t) accept(sock, &addr, &i);
                if (connection == -1) {
                    version (Windows) {
                        const err = WSAGetLastError();
                        if (err == WSAEINTR)
                            break;
                        else
                            receiver.setError(new Exception("accept "~err.to!string));

                    } else {
                        if (errno == EINTR)
                            break;
                        else
                            receiver.setError(new Exception("accept "~errno.to!string));
                    }
                    return;
                }
                int opt = 1;
                setsockopt(connection, IPPROTO_TCP, TCP_NODELAY, &opt, opt.sizeof);
                try {
                    dg(connection);
                } catch (Exception e) {
                    receiver.setError(e);
                    return;
                }
            }
            receiver.setValue();
        }
    }

    return fromStreamOp!(socket_t, void, ServerStreamOp)(sock);
}

import mir.algebraic : Algebraic;
struct Result(T, Error) {
    private Algebraic!(T, Error) data;
    alias data this;
    this(T t) {
        import core.lifetime: forward;
        data = forward!t;
    }
    this(Error e) {
        import core.lifetime: forward;
        data = forward!e;
    }
    T unwrap() {
        import mir.algebraic : match;
        import std.conv : to;
        static T rethrow(Error e) {
            static if (is (Error == Exception))
                throw e;
            else
                throw new Exception(e.to!string);
        }
        return data.match!(rethrow, (ref t) => t);
    }
    T trustedGet() nothrow {
        return data.trustedGet!T;
    }
    bool isError() {
        return data._is!Error;
    }
    bool isSuccess() {
        return data._is!T;
    }
}

Result!(socket_t, string) openListeningSocket(string host, ushort port) @trusted nothrow {
    import core.sys.windows.windows;
    import core.sys.posix.sys.socket;
    import core.sys.posix.netinet.in_;

    socket_t sock = cast(socket_t) socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return typeof(return)("socket error");

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    auto lh = host;
    if (lh.length) {
        import std.string : toStringz;

        uint uiaddr = ntohl(inet_addr(lh.toStringz()));
        if (INADDR_NONE == uiaddr) {
            return typeof(return)("bad listening host given, please use an IP address.\nExample: --listening-host 127.0.0.1 means listen only on Localhost.\nExample: --listening-host 0.0.0.0 means listen on all interfaces.\nOr you can pass any other single numeric IPv4 address.");

        }
        addr.sin_addr.s_addr = htonl(uiaddr);
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    int on = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, on.sizeof);
    version (Windows) {} else // on windows REUSEADDR includes REUSEPORT
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, on.sizeof);

    if (bind(sock, cast(sockaddr*) &addr, addr.sizeof) == -1) {
        closeSocket(sock);
        return typeof(return)("bind error");
    }

    if (listen(sock, 128) == -1) {
        closeSocket(sock);
        return typeof(return)("listen error");
    }
    return typeof(return)(sock);
}

void closeSocket(socket_t sock) @safe nothrow {
    import core.sys.posix.unistd;
    import core.sys.windows.windows;

    version (Windows) {
        closesocket(sock);
    } else {
        close(sock);
    }
}
