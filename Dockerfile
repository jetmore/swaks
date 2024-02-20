FROM alpine:3.9.6
LABEL maintainer="Bryan CS <@iambryancs>"

RUN apk add --update perl curl perl-net-ssleay

RUN curl -O https://jetmore.org/john/code/swaks/files/swaks-20201014.0/swaks

RUN chmod +x ./swaks

ENTRYPOINT ["./swaks"]

CMD ["--help"]
