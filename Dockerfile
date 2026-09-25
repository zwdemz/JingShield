FROM node:22-bookworm-slim AS ui
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=ui /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /jingshield ./cmd/jingshield

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --home-dir /var/lib/jingshield jingshield && mkdir -p /etc/jingshield /var/lib/jingshield/logs /var/lib/jingshield/data && chmod 755 /etc/jingshield && chown -R jingshield:jingshield /var/lib/jingshield
WORKDIR /var/lib/jingshield
COPY --from=build /jingshield /usr/local/bin/jingshield
COPY --chmod=0644 deploy/docker/config.yaml /etc/jingshield/config.yaml
USER jingshield
EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/jingshield", "serve", "-c", "/etc/jingshield/config.yaml"]
