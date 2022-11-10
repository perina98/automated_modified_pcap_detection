# Metody detekcie pre jednotlivé pcap súbory z datasetu:

1. - Zmena adresy z 10.3.4.42 na 10.152.1.200
   1. Skontrolovať checksum, ip adresy v aplikačnej vrstve
2. - Zmena portov z 80 na 8080 a z 22 na 8022
   1. Znova skontrolovať checksum, a porty ktoré sú v danom pakete v iných vrsvách
3. - Zmena adresy a portov
   1. Kombinácia predošlích návrhov
4. - Zmena DNS domény v DNS query
   1. Kontrola DNS answer a porovnanie s DNS query - gethostbyaddr alebo gethostbyname
5. - Zmena payloadu
   1. Kontrola dĺžky paketu
   2. Kontrola checksum
   3. Kontrola či payload končí neobvykle na 0
6. - Zmena source mac adres pri všetkých paketoch
   1. Kontrola application layer
   2. Kontrola checksum a dlžky paketu
7. - Zmena dst mac adres pri všetkých paketoch
   1. Kontrola application layer
   2. Kontrola checksum a dlžky paketu
8. - Zmena oboch source aj dst mac adres pri všetkých paketoch
   1. Kontrola application layer
   2. Kontrola checksum a dlžky paketu
9. - Zmena source mac adresy pre source IP adresu 10.2.2.27
   1. Kontrola iných layers
   2. Kontrola checksum
10. - Zmena dst mac adresy pre dst IP adresu 4.122.55.7
11. - Zmena protokolu na UDP pre src IP adresu 10.2.2.27
12. - Odstránenie payloadu pre src IP adresu 10.2.2.27
13. - Zmena DNS response ip adresy na 1.1.1.1
14. - Zmena src IP adresy, src portu a src MAC adresy
15. - Zmena protokolu na UDP a src IP adresy na IP 1.1.1.1
16. - Ak ide o DHCP, zmena protokolu na ICMP a zmena src mac adresy a src ip adresy