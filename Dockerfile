FROM golang:alpine

# docker build -t monitoro:1.0 .
# docker run -it --rm -p 9000:9000 -e MONITORO_SECRET_KEY=captainjacksparrowsayshi --name monitoro monitoro:1.0

RUN mkdir /app
COPY . /app
WORKDIR /app

RUN go build -o main app/main.go
RUN adduser -S -D -H -h /app appuser

USER appuser

ENTRYPOINT ["./main"]

EXPOSE 9000