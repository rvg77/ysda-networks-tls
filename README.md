# YSDA TLS client

TLS-client поверх OpenSSL library по мотивам [вот этого туториала](https://wiki.openssl.org/index.php/SSL/TLS_Client).

## Что под капотом

- C++, Cmake
- [OpenSSL](https://www.openssl.org) 1.1 - TLS API
- [cxxopts](https://github.com/jarro2783/cxxopts) - для парсинга аргументов
- Docker для сборки окружения

Собиралось и тестировалось все на платформе Mac M1 Pro.

## Сборка и запуск окружения

1. Собираем докер:
```bash
docker build -t ysda-networks-tls-env .
```
2. Команда запуска:
```bash
docker run --rm -it -v "./:/home/ysda-networks-tls/:rw" ysda-networks-tls-env /bin/bash
```

## Сборка и запуск клиента

1. Создаем `build` директорию:
```bash
cd /home/ysda-networks-tls && mkdir build && cd build
```
5. Сборка:
```bash
cmake .. && make
```

Функциональность клиента можно легко глянуть через `--help`:
```bash
$ ./tls_client --help
YSDA networks home assignment
Usage:
  tls_client [OPTION...] <host> <resource>

  -v, --version arg  TLS protocol version, chooose from: 1.2, 1.3 (default:
                     1.2)
  -c, --ciphers arg  Supported ciphersuites
  -k, --keylog arg   Filename to print keylog to
  -h, --help         Print usage
```

### Пример для TLS 1.2

```bash
./tls_client google.com / -v 1.2 --ciphers TLSv1.2 --keylog "../tls-1.2.keylog"
```

### Пример для TLS 1.3

```bash
./tls_client example.org / -v 1.3 --ciphers TLS_CHACHA20_POLY1305_SHA256 --keylog "../tls-1.3.keylog"
```
