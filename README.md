# WebTransport File Uploader

This repo contains a minimal working example of a file uploading app utilizing WebTransport, a new protocol for streaming over HTTP/3. Written in Go, thanks to excellent HTTP/3 and WebTransport support in these two modules:

- https://github.com/quic-go/quic-go
- https://github.com/quic-go/webtransport-go

This app was written to test WebTransport performance for transferring large files. **This application will eat your homework, and do worse. Do not use for any kind of real-life setup.**

## Running

- Install dependencies with `go mod tidy`
- Run with `go run main.go`
    - The application will print out an auth token. Store it -- you will need it to connect to the frontend.
- Connect to the frontend at `http://localhost:9090?token=<auth_token>`

## Backend

The backend will listen on `http://localhost:9090` (UDP), with the upload route `/uploadFile`. You can add `?fileName=foo` to the query string to specify the name for the file.