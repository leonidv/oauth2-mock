FROM debian:bookworm-slim

LABEL org.opencontainers.image.description ="Simple OAuth2 mock server. Only for testing purposes."
LABEL org.opencontainers.image.authors="leonid.vygovsky@gmail.com"
LABEL org.opencontainers.image.url="https://github.com/leonidv/oauth2-mock"
LABEL org.opencontainers.image.source="https://github.com/leonidv/oauth2-mock"

COPY ./target/release/oauth2-mock /
#EXPOSE 3000
RUN chmod +x /oauth2-mock

ENTRYPOINT ["/oauth2-mock"]

