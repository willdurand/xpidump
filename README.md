# xpidump

A simple tool to dump information about XPI files.

## Usage

### CLI

```
$ make release-cli
$ ./target/release/xpidump --help
A simple tool to dump information about XPI files

Usage: xpidump --input <INPUT>

Options:
  -i, --input <INPUT>  Input XPI file
  -h, --help           Print help
  -V, --version        Print version
```

### Web App

See: https://williamdurand.fr/xpidump/

## Development

```
$ make bootstrap
```

### CLI

```
$ make cli-dev xpi=<path to a XPI file>
```

### Web App

You can build and run the web app in development mode with the following command:

```
$ make dev
```

## License

xpidump is released under the MIT License. See the bundled [LICENSE](./LICENSE) file for details.
