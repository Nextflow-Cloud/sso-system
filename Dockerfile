FROM rust:1.63.0

WORKDIR /usr/app
COPY . .
RUN cargo install --path .
CMD ["sso-system"]
