FROM rust:1.66.1

WORKDIR /usr/app
COPY . .
RUN cargo install --path .
CMD ["sso-system"]
