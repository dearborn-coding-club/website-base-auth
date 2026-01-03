## Auth
> An auth server for `dearborncodingclub.com`.

This repo contains a Go server that is used for authentication on the dearborncodingclub.com website.

### Set Up Environment Variables
Copy the sample `.env` file and configure your environment variables:

```bash
cp .env.example .env
```
Modify `.env` as needed:

```bash
export POSTGRESQL_PASSWORD=password
export POSTGRESQL_NAME=db_name
export POSTGRESQL_USER=db_user
export POSTGRESQL_HOST_ISOLATED=db_host.some_website.com
export POSTGRESQL_PORT=5432
export HMAC_SECRET=your_hmac_secret_here
```

Run source to set the env for the terminal

```bash
source .env
```

### Getting started with Docker
1. To run the server, ensure that you have [Docker desktop](https://www.docker.com/get-started/) installed locally.
2. Log in to docker with `docker login`.
3. Spin up composed container with `docker compose up --build`.
4. Navigate to `localhost:8080` to access the `auth` API.

#### Getting started without Docker
1. To run the server, ensure that you have [`Go`](https://go.dev/doc/install) installed locally on your system.
2. Run `go mod vendor` from the root director.
3. Run `go run ./cmd/main.go` to spin up the server.
4. Navigate to `localhost:8080`.


> [!NOTE]
> There are a series of environment variables that should exist in a `.env` file at the root of your clone of this repo. Please reach out to one of the maintainers to get access to the right vars to hook everything up.