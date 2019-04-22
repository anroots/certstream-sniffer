# certstream-sniffer

Use [Certificate Transparency Logs][ct-logs] to discover new domains.

## Architecture

`certstream_listener.py` connects to a live stream of CT log events. Operator defines interesting top level domains
(`.com`, `.eu` etc) and when a new cert for a domain under these TLD-s is found, it gets pushed to the attached Redis
database with a short TTL (5 minutes by default).

`webserver.py` serves a simple JSON API that queries Redis and displays existing domain names out.

You are meant to periodically (once a minute) scrape the web API to get a list of potentially new domains.
Domains in the list are automatically garbage collected by Redis once TTL is over.

## Usage

```bash
$ docker-compose build
$ docker-compose up
$ curl --silent --user cert:sniffer http://localhost:8080/get-domains | jq
```

## API Doc

### /get-domains

Returns a list of domain names that were discovered from CT logs. The list changes as Redis gets updated with
new domains by `certstream_listener`; or when existing keys expire.

#### Request

- Args: none
- Auth: Basic auth

#### Response

```json
[
  {
    "domain": "google.com"
  },
  {
    "domain": "sqroot.eu"
  }
]

```

## License

MIT license

[ct-logs]: https://www.certificate-transparency.org/
