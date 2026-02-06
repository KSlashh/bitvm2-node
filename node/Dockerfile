# Container image that runs your code
FROM ubuntu:latest

# Copy binaries into the container
COPY target/release/* /usr/local/bin/
COPY node/entrypoint.sh /entrypoint.sh

RUN apt update && apt install sqlite3 ca-certificates -y && update-ca-certificates

# should map your .env to /app/.env
WORKDIR /app

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/entrypoint.sh"]
