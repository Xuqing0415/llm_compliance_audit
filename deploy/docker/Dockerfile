FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o llm-audit-gateway cmd/gateway/main.go

FROM alpine:3.19

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/llm-audit-gateway .
COPY --from=builder /app/configs/config.yaml ./configs/config.yaml
COPY --from=builder /app/configs/exemptions.yaml ./configs/exemptions.yaml

RUN mkdir -p /app/logs/audit

EXPOSE 8080 9090

ENV CONFIG_PATH=/app/configs/config.yaml

CMD ["./llm-audit-gateway", "-config", "/app/configs/config.yaml"]
