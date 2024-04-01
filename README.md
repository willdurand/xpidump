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
