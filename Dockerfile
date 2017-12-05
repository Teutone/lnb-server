FROM scratch

WORKDIR /lnb-server
ADD main .
ADD static .
# set a health check
HEALTHCHECK --interval=5s \
            --timeout=5s \
            CMD curl -f http://127.0.0.1:8080 || exit 1

EXPOSE 8080

CMD ["/lnb-server/main"]

RUN ["/lnb-server/main", "/lnb-server/data/config.json"]