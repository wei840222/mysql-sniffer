# mysql-sniffer

```
mysql_sniffer is a packet capture tool based on the MySQL protocol,
used to capture real-time requests from the MySQL server and format the output.
The output includes user access, access time, source IP, and executed SQL statements.
```

## introduction

```
usage: mysql_sniffer [-h] -p PORT [-t TABLES [TABLES ...]] [-l LOG] [-c] [-r RUNTIME] [-v]

MySQL packet sniffer

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  MySQL server port
  -t TABLES [TABLES ...], --tables TABLES [TABLES ...]
                        Table names to capture
  -l LOG, --log LOG     Log file path
  -c, --console         Print log to console
  -r RUNTIME, --runtime RUNTIME
                        Runtime of packet sniffing in seconds
  -v, --version         show program's version number and exit
```

## dependency

libpcap-dev
