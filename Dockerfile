FROM golang

WORKDIR /app
COPY . .
ENTRYPOINT ["/app/KOAuth"]
