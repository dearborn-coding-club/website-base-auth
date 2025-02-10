## Auth
> An auth server for `dearborncodingclub.com`.

This repo contains a Go server that is used for authentication on the dearborncodingclub.com website.

### Getting started
1. To run the server, ensure that you have `Go` installed locally on your system.
2. Run `go mod vendor` from the root director.
3. Run `go run ./cmd/main.go` to spin up the server.

> [!NOTE]
> There are a series of environment variables that should exist in a `.env` file at the root of your clone of this repo. Please reach out to one of the maintainers to get access to the right vars to hook everything up.