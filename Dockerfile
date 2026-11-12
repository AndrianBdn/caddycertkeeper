FROM caddy:2.11.9-builder AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY . /build/caddycertkeeper/

RUN xcaddy build \
    --with github.com/AndrianBdn/caddycertkeeper=/build/caddycertkeeper

FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/caddy /usr/bin/caddy

EXPOSE 80 443 2019

ENTRYPOINT ["/usr/bin/caddy"]

CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
