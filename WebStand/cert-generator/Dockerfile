FROM alpine:3.20

RUN apk add --no-cache openssl

COPY generate.sh /usr/local/bin/generate.sh
RUN chmod 755 /usr/local/bin/generate.sh

ENTRYPOINT ["/usr/local/bin/generate.sh"]
