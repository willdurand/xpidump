# xpidump

A simple tool to dump information about XPI files.

## Usage

### Web App

See: https://williamdurand.fr/xpidump/

### CLI

Install from GitHub via [cargo][]:

```
cargo install --git=https://github.com/willdurand/xpidump --features=cli
```

A new `xpidump` tool should be available:

```
$ xpidump --help
A simple tool to dump information about XPI files

Usage: xpidump [OPTIONS] <FILE>

Arguments:
  <FILE>  The path to an XPI file

Options:
  -f, --format <FORMAT>  [default: text] [possible values: text, json]
  -h, --help             Print help
  -V, --version          Print version
```

#### Examples

```
$ xpidump tests/fixtures/amo_info-1.25.0.xpi
MANIFEST:
  ID     : {db55bb9b-0d9f-407f-9b65-da9dd29c8d32}
  Version: 1.25.0

RECOMMENDATION:
  NONE

SIGNATURES:
  PKCS7:
   └── PRESENT / PRODUCTION / SHA-1 / REGULAR ADD-ON
   └── Certificates:
        └── Common Name         (CN): signingca1.addons.mozilla.org
            Organizational Unit (OU): Mozilla AMO Production Signing Service
        └── Common Name         (CN): {db55bb9b-0d9f-407f-9b65-da9dd29c8d32}
            Organizational Unit (OU): Production
  COSE:
   └── PRESENT / PRODUCTION / ES256 / REGULAR ADD-ON
   └── Certificates:
        └── Common Name         (CN): signingca1.addons.mozilla.org
            Organizational Unit (OU): Mozilla AMO Production Signing Service
        └── Common Name         (CN): {db55bb9b-0d9f-407f-9b65-da9dd29c8d32}
            Organizational Unit (OU): Production
```

```
$ xpidump tests/fixtures/amo_info-1.25.0.xpi --format=json
{
  "manifest": {
    "present": true,
    "id": "{db55bb9b-0d9f-407f-9b65-da9dd29c8d32}",
    "version": "1.25.0"
  },
  "signatures": {
    "pkcs7": {
      "present": true,
      "algorithm": "SHA-1",
      "certificates": [
        {
          "common_name": "signingca1.addons.mozilla.org",
          "organizational_unit": "Mozilla AMO Production Signing Service"
        },
        {
          "common_name": "{db55bb9b-0d9f-407f-9b65-da9dd29c8d32}",
          "organizational_unit": "Production"
        }
      ]
    },
    "cose": {
      "present": true,
      "algorithm": "ES256",
      "certificates": [
        {
          "common_name": "signingca1.addons.mozilla.org",
          "organizational_unit": "Mozilla AMO Production Signing Service"
        },
        {
          "common_name": "{db55bb9b-0d9f-407f-9b65-da9dd29c8d32}",
          "organizational_unit": "Production"
        }
      ]
    }
  },
  "recommendation": null
}
```

## Development

```
make bootstrap
```

### CLI

```
make cli-dev xpi=<path to a XPI file>
```

### Web App

You can build and run the web app in development mode with the following command:

```
make dev
```

## License

xpidump is released under the MIT License. See the bundled [LICENSE](./LICENSE) file for details.

[cargo]: https://doc.rust-lang.org/cargo/
