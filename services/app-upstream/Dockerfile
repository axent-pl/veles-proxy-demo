# Etap build
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN mkdir out
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/kerb-app ./main.go

# Etap runtime
FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/kerb-app /app/kerb-app
# keytab i krb5.conf wejdą jako volume
ENV APP_PORT=8080
USER 65532:65532
ENTRYPOINT ["/app/kerb-app"]