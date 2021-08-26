FROM golang:1.16-buster AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

RUN go build -o /harbor-scanner-fake


# hadolint ignore=DL3006
FROM gcr.io/distroless/base-debian10

WORKDIR /

COPY --from=build /harbor-scanner-fake /harbor-scanner-fake

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/harbor-scanner-fake"]
