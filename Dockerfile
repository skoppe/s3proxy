FROM ubuntu

RUN apt -qq update && apt -qq -y install tzdata openssl ca-certificates

RUN useradd -m s3proxy

USER s3proxy
WORKDIR /home/s3proxy

COPY --chown=s3proxy:s3proxy s3proxy /home/s3proxy/
RUN chmod +x /home/s3proxy/s3proxy

ENTRYPOINT ["./s3proxy"]
