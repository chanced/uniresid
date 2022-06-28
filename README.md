# Uri

This is a library which implements [IETF RFC
3986](https://tools.ietf.org/html/rfc3986), "Uniform Resource Identifier (URI):
Generic Syntax".

More information about this library can be found in
the [crate documentation](https://docs.rs/uris).

A URI is a compact sequence of characters that identifies an abstract or
physical resource. One common form of URI is the Uniform Resource Locator
(URL), used to reference web resources:

    http://www.example.com/foo?bar#baz

Another kind of URI is the path reference:

    /usr/bin/zip

The purpose of this library is to provide a `Uri` type to represent a URI,
with functions to parse URIs from their string representations, as well as
assemble URIs from their various components.

## Credits

This crate has been forked from [uris](https://crates.io/crates/uris). Thanks to
Richard Walters for the [original implementation](https://crates.io/crates/uris)
and Richard Walters for his improvements.

## License

Licensed under the [MIT license](LICENSE.txt).
