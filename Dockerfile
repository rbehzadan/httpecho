FROM golang:1.24.1-alpine AS builder

WORKDIR /src

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /httpecho main.go


FROM alpine:latest

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /httpecho httpecho

RUN chown appuser:appgroup /app/httpecho \
  && chmod +x /app/httpecho

ENV PORT=3000
ENV MAX_BODY_SIZE=1048576
ENV RATE_LIMIT=100
ENV RATE_WINDOW=60
ENV HTML_MODE=false

USER appuser

EXPOSE 3000

CMD ["/app/httpecho"]

