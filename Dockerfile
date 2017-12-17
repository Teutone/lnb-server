FROM ubuntu:latest

WORKDIR /lnb-server
RUN mkdir -p data
ADD main .
ADD config/default.json data/config.json
ADD static .

EXPOSE 8080

ENTRYPOINT ["/lnb-server/main"]
CMD ["data/config.json"]
