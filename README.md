# insight-sdk

Library firmware **C++ (Arduino)** untuk ESP32/ESP8266: keandalan lapangan (timeout, retry/backoff, buffer RAM, watchdog) + OTA SHA-256.

**Status:** early / skeleton.

## Menjalankan

```bash
pio test -e native            # test logika di host (tanpa hardware)
pio ci --board esp32dev --lib . examples/Blink
pio ci --board nodemcuv2 --lib . examples/Blink   # ESP8266
```

## Lisensi

MIT © zalhashfi
