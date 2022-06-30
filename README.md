# **u**ni**r**es**i**d

[<img alt="github" src="https://img.shields.io/badge/github-chanced/uniresid-8da0cb?style=for-the-badge&labelColor=777&logo=github" height="20">](https://github.com/chanced/uniresid)
[<img alt="crates.io" src="https://img.shields.io/crates/v/uniresid.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/uniresid)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-uniresid-f0f0f0?style=for-the-badge&labelColor=777&logo=docs.rs" height="20">](https://docs.rs/uniresid)
[<img alt="build status" src="https://img.shields.io/github/workflow/status/chanced/uniresid/Rust/main?style=for-the-badge" height="20">](https://github.com/chanced/uniresid/actions?query=branch%3Amain)

**U**niform **R**esource **I**dentifiers ([RFC
3986](https://tools.ietf.org/html/rfc3986)) for rust.

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
Richard Walters for the [original implementation](https://crates.io/crates/rhymuri)
and Martin Fischer for his improvements.

## License

Licensed under the [MIT license](LICENSE.txt).
