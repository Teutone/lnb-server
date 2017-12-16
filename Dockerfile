FROM alpine:latest

WORKDIR /lnb-server
RUN mkdir -p data
ADD main .
ADD config/default.json data/config.json
ADD static .

EXPOSE 8080

CMD ["/lnb-server/main", "/lnb-server/data/config.json"]
