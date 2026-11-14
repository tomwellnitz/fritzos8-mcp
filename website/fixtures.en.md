# Community fixtures

Tests only run against mocks. Anonymized real answers from more models and FRITZ!OS versions make the server fit all boxes.

```bash
fritzos8-anonymize answer.json --kind tr064 --model "FRITZ!Box 7590" --fritzos 8.20 \
  --name tr064-Hosts1-GetGenericHostEntry -o tests/fixtures/community/7590-8.20-hosts.json
```

MAC addresses, IPv4/IPv6 addresses, device/host/Wi-Fi/user names, serial numbers/UUIDs/AINs, phone numbers, e-mail addresses, DynDNS names and location data are replaced consistently; secrets are redacted. The tool refuses to write if anything still looks real. Review the file by hand (free texts!) and open a pull request with model, FRITZ!OS version and access type. CI checks every file in `tests/fixtures/community/`.
