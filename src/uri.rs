use crate::AbsoluteUri;

use super::{
    authority::Authority,
    character_classes::{
        ALPHA, PCHAR_NOT_PCT_ENCODED, QUERY_NOT_PCT_ENCODED_WITHOUT_PLUS,
        QUERY_OR_FRAGMENT_NOT_PCT_ENCODED, SCHEME_NOT_FIRST,
    },
    codec::{decode_element, encode_element},
    context::Context,
    error::Error,
};
use std::{collections::HashSet, convert::TryFrom, ops::Deref};
use std::{fmt::Write, string::FromUtf8Error};

/// This type is used to parse and generate URI strings to and from their
/// various components.  Components are percent-encoded as necessary during
/// generation, and percent encodings are decoded during parsing.
///
/// Since most URI components, once decoded, may include non-UTF8 byte
/// sequences (which are always percent-encoded), getter methods such as
/// [`path`] and [`query`] return byte array [slice] references (`&[u8]`)
/// rather than string or string slice references.  Fallible convenience
/// methods ending in `_to_string`, such as [`path_to_string`] and
/// [`query_to_string`], are provided to convert these to strings.
///
/// The "Authority" part of the Uri is represented by the [`Authority` type].
/// Although the `Uri` type provides [`user_info`], [`host`], and [`port`]
/// methods for convenience, `Uri` holds these components through the
/// [`Authority` type], which can be accessed via [`authority`] and
/// [`set_authority`].  To set or change the `user_info`, host, or port of a
/// `Uri`, construct a new `Authority` value and set it in the `Uri` with
/// [`set_authority`].
///
/// # Examples
///
/// ## Parsing a URI into its components
///
/// ```rust
/// use uniresid::Uri;
///
/// # fn main() {
/// let uri = Uri::parse("http://www.example.com/foo?bar#baz").unwrap();
/// let authority = uri.authority().unwrap();
/// assert_eq!("www.example.com".as_bytes(), authority.host());
/// assert_eq!(Some("www.example.com"), uri.host_to_string().unwrap().as_deref());
/// assert_eq!("/foo", uri.path_to_string().unwrap());
/// assert_eq!(Some("bar"), uri.query_to_string().unwrap().as_deref());
/// assert_eq!(Some("baz"), uri.fragment_to_string().unwrap().as_deref());
/// # }
/// ```
///
/// Implementations are provided for the [`TryFrom`] trait, so that
/// [`TryFrom::try_from`] or [`TryInto::try_into`] may be used as alternatives
/// to [`parse`].
///
/// ## Generating a URI from its components
///
/// ```rust
/// use uniresid::{ Authority, Uri };
///
/// let mut uri = Uri::default();
/// assert!(uri.set_scheme(String::from("http")).is_ok());
/// let mut authority = Authority::default();
/// authority.set_host("www.example.com");
/// uri.set_authority(Some(authority));
/// uri.set_path_from_str("/foo");
/// uri.set_query(Some("bar".into()));
/// uri.set_fragment(Some("baz".into()));
/// assert_eq!("http://www.example.com/foo?bar#baz", uri.to_string());
/// ```
///
/// [`authority`]: #method.authority
/// [`Authority` type]: struct.Authority.html
/// [`host`]: #method.host
/// [`parse`]: #method.parse
/// [`path`]: #method.path
/// [`path_to_string`]: #method.path_to_string
/// [`port`]: #method.port
/// [`query`]: #method.query
/// [`query_to_string`]: #method.query_to_string
/// [`set_authority`]: #method.set_authority
/// [`user_info`]: #method.user_info
/// [slice]: https://doc.rust-lang.org/std/primitive.slice.html
/// [`TryFrom::try_from`]: https://doc.rust-lang.org/std/convert/trait.TryFrom.html#tymethod.try_from
/// [`TryInto::try_into`]: https://doc.rust-lang.org/std/convert/trait.TryInto.html#tymethod.try_into
#[derive(Clone, Default, Hash, PartialEq, Eq)]
pub struct Uri {
    scheme: Option<String>,
    authority: Option<Authority>,
    path: Vec<Vec<u8>>,
    query: Option<Vec<u8>>,
    fragment: Option<Vec<u8>>,
    raw: String,
}

impl Uri {
    /// Borrow the authority (if any) of the URI.
    #[must_use = "authority not used"]
    pub fn authority(&self) -> Option<&Authority> {
        self.authority.as_ref()
    }

    /// Determines if the URI contains a relative path rather than an absolute
    /// path.
    #[must_use]
    pub fn contains_relative_path(&self) -> bool {
        !Self::is_path_absolute(&self.path)
    }

    /// Borrow the fragment (if any) of the URI.
    #[must_use]
    pub fn fragment(&self) -> Option<&[u8]> {
        self.fragment.as_deref()
    }

    /// Convert the fragment (if any) into a string.
    ///
    /// # Errors
    ///
    /// Since fragments may contain non-UTF8 byte sequences, this function may
    /// return [`Error::CannotExpressAsUtf8`][CannotExpressAsUtf8].
    ///
    /// [CannotExpressAsUtf8]: enum.Error.html#variant.CannotExpressAsUtf8
    pub fn fragment_to_string(&self) -> Result<Option<String>, FromUtf8Error> {
        self.fragment()
            .map(|fragment| String::from_utf8(fragment.to_vec()).map_err(Into::into))
            .transpose()
    }

    /// Borrow the host portion of the Authority (if any) of the URI.
    #[must_use]
    pub fn host(&self) -> Option<&[u8]> {
        self.authority.as_ref().map(Authority::host)
    }

    /// Convert the host portion of the Authority (if any) into a string.
    ///
    /// # Errors
    ///
    /// Since host names may contain non-UTF8 byte sequences, this function may
    /// return [`Error::CannotExpressAsUtf8`][CannotExpressAsUtf8].
    ///
    /// [CannotExpressAsUtf8]: enum.Error.html#variant.CannotExpressAsUtf8
    pub fn host_to_string(&self) -> Result<Option<String>, FromUtf8Error> {
        self.host()
            .map(|host| String::from_utf8(host.to_vec()))
            .transpose()
    }

    /// Determines if the URI is a `relative-ref` (relative reference), as
    /// defined in [RFC 3986 section
    /// 4.2](https://tools.ietf.org/html/rfc3986#section-4.2).  A relative
    /// reference has no scheme, but may still have an authority.
    #[must_use]
    pub fn is_relative_reference(&self) -> bool {
        self.scheme.is_none()
    }

    /// Apply the `remove_dot_segments` routine talked about
    /// in [RFC 3986 section
    /// 5.2](https://tools.ietf.org/html/rfc3986#section-5.2) to the path
    /// segments of the URI, in order to normalize the path (apply and remove
    /// "." and ".." segments).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use uniresid::Uri;
    ///
    /// # fn main() {
    /// let mut uri = Uri::parse("/a/b/c/./../../g").unwrap();
    /// uri.normalize();
    /// assert_eq!("/a/g", uri.path_to_string().unwrap());
    /// # }
    /// ```
    pub fn normalize(&mut self) {
        self.path = Self::normalize_path(&self.path);
        self.update_raw();
    }

    /// Interpret the given string as a URI, separating its various components,
    /// returning a `Uri` value containing them.
    ///
    /// # Errors
    ///
    /// There are many ways to screw up a URI string, and this function will
    /// let you know what's up by returning a variant of the
    /// [`Error`](enum.Error.html) type.
    pub fn parse<T>(uri_string: T) -> Result<Self, Error>
    where
        T: AsRef<str>,
    {
        let s = uri_string.as_ref();
        let (scheme, rest) = Self::parse_scheme(s)?;
        let path_end = rest.find(&['?', '#'][..]).unwrap_or(rest.len());
        let authority_and_path_string = &rest[0..path_end];
        let query_and_or_fragment = &rest[path_end..];
        let (authority, path) =
            Self::split_authority_from_path_and_parse_them(authority_and_path_string)?;
        let (fragment, possible_query) = Self::parse_fragment(query_and_or_fragment)?;
        let query = Self::parse_query(possible_query)?;
        let mut this = Self {
            scheme,
            authority,
            path,
            query,
            fragment,
            raw: String::default(),
        };
        this.update_raw();
        Ok(this)
    }

    /// Borrow the path component of the URI.
    ///
    /// The path is represented as a two-dimensional vector:
    /// * the "segments" or pieces of the path between the slashes
    /// * the bytes that make up each segment
    ///
    /// Byte vectors are used instead of strings because segments may contain
    /// non-UTF8 sequences.
    ///
    /// Leading and trailing slashes in the path are special cases represented
    /// by extra empty segments at the beginning and/or end of the path.
    ///
    /// # Examples
    ///
    /// (Note: the examples below show strings, not byte vectors, simply to be
    /// more readable.)
    ///
    /// ```text
    /// "foo/bar"   -> ["foo", "bar"]
    /// "/foo/bar"  -> ["", "foo", "bar"]
    /// "foo/bar/"  -> ["foo", "bar", ""]
    /// "/foo/bar/" -> ["", "foo", "bar", ""]
    /// "/"         -> [""]
    /// ""          -> []
    /// ```
    #[must_use]
    pub fn path(&self) -> &Vec<Vec<u8>> {
        &self.path
    }

    /// Convert the path portion of the URI into a string.
    ///
    /// # Errors
    ///
    /// Since path segments may contain non-UTF8 byte sequences, this function
    /// may return
    /// [`Error::CannotExpressAsUtf8`][CannotExpressAsUtf8].
    ///
    /// [CannotExpressAsUtf8]: enum.Error.html#variant.CannotExpressAsUtf8
    pub fn path_to_string(&self) -> Result<String, FromUtf8Error> {
        match &*self.path {
            [segment] if segment.is_empty() => Ok("/".to_string()),
            path => Ok(String::from_utf8(path.join(&b"/"[..]))?),
        }
    }

    /// Return a copy of the port (if any) contained in the URI.
    pub fn port(&self) -> Option<u16> {
        self.authority.as_ref().and_then(Authority::port)
    }

    /// Borrow the query (if any) of the URI.
    #[must_use]
    pub fn query(&self) -> Option<&[u8]> {
        self.query.as_deref()
    }

    /// Convert the query (if any) into a string.
    ///
    /// # Errors
    ///
    /// Since queries may contain non-UTF8 byte sequences, this function may
    /// return [`Error::CannotExpressAsUtf8`][CannotExpressAsUtf8].
    ///
    /// [CannotExpressAsUtf8]: enum.Error.html#variant.CannotExpressAsUtf8
    pub fn query_to_string(&self) -> Result<Option<String>, FromUtf8Error> {
        self.query()
            .map(|query| String::from_utf8(query.to_vec()))
            .transpose()
    }

    /// Return a new URI which is the result of applying the given relative
    /// reference to the URI, following the algorithm from [RFC 3986 section
    /// 5.2.2](https://tools.ietf.org/html/rfc3986#section-5.2.2).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use uniresid::Uri;
    ///
    /// # fn main() -> Result<(), uniresid::Error> {
    /// let base = Uri::parse("http://a/b/c/d;p?q")?;
    /// let relative_reference = Uri::parse("g;x?y#s")?;
    /// let resolved = base.resolve(&relative_reference);
    /// assert_eq!("http://a/b/c/g;x?y#s", resolved.to_string());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn resolve(&self, relative_reference: &Self) -> Self {
        let (scheme, authority, path, query) = if relative_reference.scheme.is_some() {
            (
                relative_reference.scheme.clone(),
                relative_reference.authority.clone(),
                Self::normalize_path(&relative_reference.path),
                relative_reference.query.clone(),
            )
        } else {
            relative_reference.authority.as_ref().map_or_else(
                || {
                    let scheme = self.scheme.clone();
                    let authority = self.authority.clone();
                    if relative_reference.path.is_empty() {
                        let path = self.path.clone();
                        let query = if relative_reference.query.is_none() {
                            self.query.clone()
                        } else {
                            relative_reference.query.clone()
                        };
                        (scheme, authority, path, query)
                    } else {
                        let query = relative_reference.query.clone();

                        // RFC describes this as:
                        // "if (R.path starts-with "/") then"
                        if Self::is_path_absolute(&relative_reference.path) {
                            (scheme, authority, relative_reference.path.clone(), query)
                        } else {
                            // RFC describes this as:
                            // "T.path = merge(Base.path, R.path);"
                            let mut path = self.path.clone();
                            if self.authority.is_none() || path.len() > 1 {
                                path.pop();
                            }
                            path.extend(relative_reference.path.iter().cloned());
                            (scheme, authority, Self::normalize_path(&path), query)
                        }
                    }
                },
                |authority| {
                    (
                        self.scheme.clone(),
                        Some(authority.clone()),
                        Self::normalize_path(&relative_reference.path),
                        relative_reference.query.clone(),
                    )
                },
            )
        };
        let mut temp = Self {
            scheme,
            authority,
            path,
            query,
            fragment: relative_reference.fragment.clone(),
            raw: String::default(),
        };
        temp.update_raw();
        temp
    }

    /// Borrow the scheme (if any) component of the URI.
    #[must_use]
    pub fn scheme(&self) -> Option<&str> {
        // NOTE: This seemingly magic `as_deref` works because of two
        // things that are going on here:
        // 1) String implements DeRef with `str` as the associated type
        //    `Target`, meaning you can use a String in a context requiring
        //    &str, and String does the conversion work.
        // 2) as_deref works by turning `Option<T>` into `Option<&T::Target>`,
        //    requiring T to implement Deref.  In this case T is String.
        self.scheme.as_deref()
    }

    /// Change the authority of the URI.
    pub fn set_authority<T>(&mut self, authority: T)
    where
        T: Into<Option<Authority>>,
    {
        self.authority = authority.into();
        self.update_raw();
    }

    /// Change the fragment of the URI.
    pub fn set_fragment<T>(&mut self, fragment: T)
    where
        T: Into<Option<Vec<u8>>>,
    {
        self.fragment = fragment.into();
        self.update_raw();
    }

    /// Change the path of the URI.
    ///
    /// Note: See [`path`](#method.path) for special notes about what the
    /// segments of the path mean.
    pub fn set_path<T>(&mut self, path: T)
    where
        T: Into<Vec<Vec<u8>>>,
    {
        self.path = path.into();
        self.update_raw();
    }

    /// Change the path of the URI using a string which is split by its slash
    /// (`/`) characters to determine the path segments.
    ///
    /// Note: See [`path`](#method.path) for special notes about what the
    /// segments of the path mean.
    pub fn set_path_from_str<T>(&mut self, path: T)
    where
        T: AsRef<str>,
    {
        match path.as_ref() {
            "" => self.set_path(vec![]),
            path => self.set_path(
                path.split('/')
                    .map(|segment| segment.as_bytes().to_vec())
                    .collect::<Vec<Vec<u8>>>(),
            ),
        }
        self.update_raw();
    }

    /// Change the query of the URI.
    pub fn set_query<T>(&mut self, query: T)
    where
        T: Into<Option<Vec<u8>>>,
    {
        self.query = query.into();
        self.update_raw();
    }

    /// Change the scheme of the URI.
    ///
    /// # Errors
    ///
    /// The set of characters allowed in the scheme of a URI is limited.
    /// [`Error::IllegalCharacter`](enum.Error.html#variant.IllegalCharacter)
    /// is returned if you try to use a character that isn't allowed.
    pub fn set_scheme<T>(&mut self, scheme: T) -> Result<(), Error>
    where
        T: Into<Option<String>>,
    {
        self.scheme = match scheme.into() {
            Some(scheme) => {
                Self::check_scheme(&scheme)?;
                Some(scheme)
            }
            None => None,
        };
        self.update_raw();
        Ok(())
    }

    // /// Remove and return the authority portion (if any) of the URI.
    // #[must_use]
    // pub fn take_authority(&mut self) -> Option<Authority> {
    //     let authority = self.authority.take();
    //     self.update_raw();
    //     authority
    // }

    // /// Remove and return the fragment portion (if any) of the URI.
    // #[must_use]
    // pub fn take_fragment(&mut self) -> Option<Vec<u8>> {
    //     let fragment = self.fragment.take();
    //     self.update_raw();
    //     fragment
    // }

    // /// Remove and return the query portion (if any) of the URI.
    // #[must_use]
    // pub fn take_query(&mut self) -> Option<Vec<u8>> {
    //     let query = self.query.take();
    //     self.update_raw();
    //     query
    // }

    // /// Remove and return the scheme portion (if any) of the URI.
    // #[must_use]
    // pub fn take_scheme(&mut self) -> Option<String> {
    //     let scheme = self.scheme.take();
    //     self.update_raw();
    //     scheme
    // }

    /// Borrow the `user_info` portion (if any) of the Authority (if any) of the
    /// URI.
    ///
    /// Note that you can get `None` if there is either no Authority in the URI
    /// or there is an Authority in the URI but it has no `user_info` in it.
    #[must_use]
    pub fn user_info(&self) -> Option<&[u8]> {
        self.authority.as_ref().and_then(Authority::user_info)
    }

    /// Convert the fragment (if any) into a string.
    ///
    /// # Errors
    ///
    /// Since fragments may contain non-UTF8 byte sequences, this function may
    /// return [`Error::CannotExpressAsUtf8`][CannotExpressAsUtf8].
    ///
    /// [CannotExpressAsUtf8]: enum.Error.html#variant.CannotExpressAsUtf8
    pub fn user_info_to_string(&self) -> Result<Option<String>, FromUtf8Error> {
        self.user_info()
            .map(|user_info| String::from_utf8(user_info.to_vec()))
            .transpose()
    }

    // ----------------------------------------------------------------------------------------------
    //                                         private methods
    // ----------------------------------------------------------------------------------------------
    fn is_path_absolute<T>(path: T) -> bool
    where
        T: AsRef<[Vec<u8>]>,
    {
        matches!(path.as_ref(), [segment, ..] if segment.is_empty())
    }

    fn decode_query_or_fragment<T>(query_or_fragment: T, context: Context) -> Result<Vec<u8>, Error>
    where
        T: AsRef<str>,
    {
        decode_element(
            query_or_fragment,
            &QUERY_OR_FRAGMENT_NOT_PCT_ENCODED,
            context,
        )
    }

    fn update_raw(&mut self) {
        let mut raw = String::new();

        if let Some(scheme) = &self.scheme {
            write!(&mut raw, "{}:", scheme).unwrap();
        }
        if let Some(authority) = &self.authority {
            write!(&mut raw, "//{}", authority).unwrap();
        }
        // Special case: absolute but otherwise empty path.
        if Self::is_path_absolute(&self.path) && self.path.len() == 1 {
            write!(&mut raw, "/").unwrap();
        }
        for (i, segment) in self.path.iter().enumerate() {
            write!(
                &mut raw,
                "{}",
                encode_element(segment, &PCHAR_NOT_PCT_ENCODED)
            )
            .unwrap();
            if i + 1 < self.path.len() {
                write!(&mut raw, "/").unwrap();
            }
        }
        if let Some(query) = &self.query {
            write!(
                &mut raw,
                "?{}",
                encode_element(query, &QUERY_NOT_PCT_ENCODED_WITHOUT_PLUS)
            )
            .unwrap();
        }
        if let Some(fragment) = &self.fragment {
            write!(
                raw,
                "#{}",
                encode_element(fragment, &QUERY_OR_FRAGMENT_NOT_PCT_ENCODED)
            )
            .unwrap();
        }

        self.raw = raw;
    }

    fn parse_fragment(query_and_or_fragment: &str) -> Result<(Option<Vec<u8>>, &str), Error> {
        if let Some(fragment_delimiter) = query_and_or_fragment.find('#') {
            let fragment = Self::decode_query_or_fragment(
                &query_and_or_fragment[fragment_delimiter + 1..],
                Context::Fragment,
            )?;
            Ok((
                Some(fragment),
                &query_and_or_fragment[0..fragment_delimiter],
            ))
        } else {
            Ok((None, query_and_or_fragment))
        }
    }

    fn parse_path<T>(path_string: T) -> Result<Vec<Vec<u8>>, Error>
    where
        T: AsRef<str>,
    {
        match path_string.as_ref() {
            "/" => {
                // Special case of an empty absolute path, which we want to
                // represent as single empty-string element to indicate that it
                // is absolute.
                Ok(vec![vec![]])
            }

            "" => {
                // Special case of an empty relative path, which we want to
                // represent as an empty vector.
                Ok(vec![])
            }

            path_string => path_string
                .split('/')
                .map(|segment| decode_element(&segment, &PCHAR_NOT_PCT_ENCODED, Context::Path))
                .collect(),
        }
    }

    fn parse_query<T>(query_and_or_fragment: T) -> Result<Option<Vec<u8>>, Error>
    where
        T: AsRef<str>,
    {
        let query_and_or_fragment = query_and_or_fragment.as_ref();
        if query_and_or_fragment.is_empty() {
            Ok(None)
        } else {
            let query =
                Self::decode_query_or_fragment(&query_and_or_fragment[1..], Context::Query)?;
            Ok(Some(query))
        }
    }

    fn parse_scheme(uri_string: &str) -> Result<(Option<String>, &str), Error> {
        // Limit our search so we don't scan into the authority
        // or path elements, because these may have the colon
        // character as well, which we might misinterpret
        // as the scheme delimiter.
        let authority_or_path_delimiter_start = uri_string.find('/').unwrap_or(uri_string.len());
        if let Some(scheme_end) = &uri_string[0..authority_or_path_delimiter_start].find(':') {
            let scheme = Self::check_scheme(&uri_string[0..*scheme_end])?.to_lowercase();
            Ok((Some(scheme), &uri_string[*scheme_end + 1..]))
        } else {
            Ok((None, uri_string))
        }
    }

    fn normalize_path<T>(original_path: T) -> Vec<Vec<u8>>
    where
        T: AsRef<[Vec<u8>]>,
    {
        // Rebuild the path one segment
        // at a time, removing and applying special
        // navigation segments ("." and "..") as we go.
        //
        // The `at_directory_level` variable tracks whether or not
        // the `normalized_path` refers to a directory.
        let mut at_directory_level = false;
        let mut normalized_path = Vec::new();
        for segment in original_path.as_ref() {
            if segment == b"." {
                at_directory_level = true;
            } else if segment == b".." {
                // Remove last path element
                // if we can navigate up a level.
                if !normalized_path.is_empty()
                    && Self::can_navigate_path_up_one_level(&normalized_path)
                {
                    normalized_path.pop();
                }
                at_directory_level = true;
            } else {
                // Non-relative elements can just
                // transfer over fine.  An empty
                // segment marks a transition to
                // a directory level context.  If we're
                // already in that context, we
                // want to ignore the transition.
                let new_at_directory_level = segment.is_empty();
                if !at_directory_level || !segment.is_empty() {
                    normalized_path.push(segment.clone());
                }
                at_directory_level = new_at_directory_level;
            }
        }

        // If at the end of rebuilding the path,
        // we're in a directory level context,
        // add an empty segment to mark the fact.
        match (at_directory_level, normalized_path.last()) {
            (true, Some(segment)) if !segment.is_empty() => {
                normalized_path.push(vec![]);
            }
            _ => (),
        }
        normalized_path
    }

    fn split_authority_from_path_and_parse_them<T>(
        authority_and_path_string: T,
    ) -> Result<(Option<Authority>, Vec<Vec<u8>>), Error>
    where
        T: AsRef<str>,
    {
        // Split authority from path.  If there is an authority, parse it.
        let authority_and_path_string = authority_and_path_string.as_ref();
        if let Some(authority_and_path_string) = authority_and_path_string.strip_prefix("//") {
            // First separate the authority from the path.
            let authority_end = authority_and_path_string
                .find('/')
                .unwrap_or(authority_and_path_string.len());
            let authority_string = &authority_and_path_string[0..authority_end];
            let path_string = &authority_and_path_string[authority_end..];

            // Parse the elements inside the authority string.
            let authority = Authority::parse(authority_string)?;
            let path = if path_string.is_empty() {
                vec![vec![]]
            } else {
                Self::parse_path(path_string)?
            };
            Ok((Some(authority), path))
        } else {
            let path = Self::parse_path(authority_and_path_string)?;
            Ok((None, path))
        }
    }

    fn can_navigate_path_up_one_level<T>(path: T) -> bool
    where
        T: AsRef<[Vec<u8>]>,
    {
        let path = path.as_ref();
        match path.first() {
            // First segment empty means path has leading slash,
            // so we can only navigate up if there are two or more segments.
            Some(segment) if segment.is_empty() => path.len() > 1,

            // Otherwise, we can navigate up as long as there is at least one
            // segment.
            Some(_) => true,
            None => false,
        }
    }

    fn check_scheme<T>(scheme: T) -> Result<T, Error>
    where
        T: AsRef<str>,
    {
        match scheme.as_ref() {
            "" => return Err(Error::EmptyScheme),
            scheme => scheme.chars().enumerate().try_fold((), |_, (i, c)| {
                let valid_characters: &HashSet<char> =
                    if i == 0 { &ALPHA } else { &SCHEME_NOT_FIRST };
                if valid_characters.contains(&c) {
                    Ok(())
                } else {
                    Err(Error::IllegalCharacter(Context::Scheme))
                }
            })?,
        };
        Ok(scheme)
    }
}

impl std::fmt::Debug for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Uri").field(&self.to_string()).finish()
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.raw)
    }
}

impl Deref for Uri {
    type Target = str;
    fn deref(&self) -> &str {
        &self.raw
    }
}

impl TryFrom<&'_ str> for Uri {
    type Error = Error;

    fn try_from(uri_string: &'_ str) -> Result<Self, Self::Error> {
        Uri::parse(uri_string)
    }
}

impl TryFrom<String> for Uri {
    type Error = Error;

    fn try_from(uri_string: String) -> Result<Self, Self::Error> {
        Uri::parse(uri_string)
    }
}

impl From<AbsoluteUri> for Uri {
    fn from(absolute_uri: AbsoluteUri) -> Self {
        absolute_uri.uri
    }
}

impl From<&AbsoluteUri> for Uri {
    fn from(absolute_uri: &AbsoluteUri) -> Self {
        absolute_uri.uri.clone()
    }
}

#[cfg(feature = "url")]
impl TryInto<Uri> for url_::Url {
    type Error = Error;
    fn try_into(self) -> Result<Uri, Self::Error> {
        Uri::parse(self)
    }
}

#[cfg(feature = "url")]
impl TryFrom<Uri> for url_::Url {
    type Error = url_::ParseError;

    fn try_from(value: Uri) -> Result<Self, Self::Error> {
        value.try_into()
    }
}

#[cfg(feature = "serde")]
impl serde_::Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde_::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde_::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde_::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uri::parse(s).map_err(serde_::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {

    use std::convert::TryInto;

    use super::*;

    #[test]
    fn no_scheme() {
        let uri = Uri::parse("foo/bar");
        assert!(uri.is_ok());
        let uri = uri.unwrap();
        assert_eq!(None, uri.scheme());
        assert_eq!(&[&b"foo"[..], &b"bar"[..]].to_vec(), uri.path());
        assert_eq!("foo/bar", uri.path_to_string().unwrap());
    }

    #[test]
    fn url() {
        let uri: Result<Uri, Error> = "http://www.example.com/foo/bar".try_into();
        assert!(uri.is_ok());
        let uri = uri.unwrap();
        assert_eq!(Some("http"), uri.scheme());
        assert_eq!(Some(&b"www.example.com"[..]), uri.host());
        assert_eq!(
            Some("www.example.com"),
            uri.host_to_string().unwrap().as_deref()
        );
        assert_eq!(uri.path_to_string().unwrap(), "/foo/bar");
    }

    #[test]
    fn urn_default_path_delimiter() {
        let uri = Uri::try_from("urn:book:fantasy:Hobbit");
        assert!(uri.is_ok());
        let uri = uri.unwrap();
        assert_eq!(Some("urn"), uri.scheme());
        assert_eq!(None, uri.host());
        assert_eq!(uri.path_to_string().unwrap(), "book:fantasy:Hobbit");
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn path_corner_cases() {
        struct Test {
            path_in: &'static str,
            path_out: Vec<&'static [u8]>,
        }
        let test_vectors: &[Test] = &[
            Test {
                path_in: "",
                path_out: vec![],
            },
            Test {
                path_in: "/",
                path_out: vec![&b""[..]],
            },
            Test {
                path_in: "/foo",
                path_out: vec![&b""[..], &b"foo"[..]],
            },
            Test {
                path_in: "foo/",
                path_out: vec![&b"foo"[..], &b""[..]],
            },
        ];
        for test_vector in test_vectors {
            let uri = Uri::parse(test_vector.path_in);
            assert!(uri.is_ok());
            let uri = uri.unwrap();

            assert_eq!(&test_vector.path_out, uri.path());
        }
    }

    #[test]
    fn uri_ends_after_authority() {
        let uri = Uri::parse("http://www.example.com");
        assert!(uri.is_ok());
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn relative_vs_non_relative_references() {
        struct Test {
            uri_string: &'static str,
            is_relative_reference: bool,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "http://www.example.com/",
                is_relative_reference: false,
            },
            Test {
                uri_string: "http://www.example.com",
                is_relative_reference: false,
            },
            Test {
                uri_string: "/",
                is_relative_reference: true,
            },
            Test {
                uri_string: "foo",
                is_relative_reference: true,
            },
        ];
        for test_vector in test_vectors {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(
                test_vector.is_relative_reference,
                uri.is_relative_reference()
            );
        }
    }

    #[test]
    fn relative_vs_non_relative_paths() {
        struct Test {
            uri_string: &'static str,
            contains_relative_path: bool,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "http://www.example.com/",
                contains_relative_path: false,
            },
            Test {
                uri_string: "http://www.example.com",
                contains_relative_path: false,
            },
            Test {
                uri_string: "/",
                contains_relative_path: false,
            },
            Test {
                uri_string: "foo",
                contains_relative_path: true,
            },
            // This is only a valid test vector if we understand
            // correctly that an empty string IS a valid
            // "relative reference" URI with an empty path.
            Test {
                uri_string: "",
                contains_relative_path: true,
            },
        ];
        for (test_index, test_vector) in test_vectors.iter().enumerate() {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(
                test_vector.contains_relative_path,
                uri.contains_relative_path(),
                "{}",
                test_index
            );
        }
    }

    #[test]
    #[allow(clippy::ref_option_ref)]
    fn query_and_fragment_elements() {
        struct Test {
            uri_string: &'static str,
            host: &'static str,
            query: Option<&'static str>,
            fragment: Option<&'static str>,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "http://www.example.com/",
                host: "www.example.com",
                query: None,
                fragment: None,
            },
            Test {
                uri_string: "http://example.com?foo",
                host: "example.com",
                query: Some("foo"),
                fragment: None,
            },
            Test {
                uri_string: "http://www.example.com#foo",
                host: "www.example.com",
                query: None,
                fragment: Some("foo"),
            },
            Test {
                uri_string: "http://www.example.com?foo#bar",
                host: "www.example.com",
                query: Some("foo"),
                fragment: Some("bar"),
            },
            Test {
                uri_string: "http://www.example.com?earth?day#bar",
                host: "www.example.com",
                query: Some("earth?day"),
                fragment: Some("bar"),
            },
            Test {
                uri_string: "http://www.example.com/spam?foo#bar",
                host: "www.example.com",
                query: Some("foo"),
                fragment: Some("bar"),
            },
            Test {
                uri_string: "http://www.example.com/?",
                host: "www.example.com",
                query: Some(""),
                fragment: None,
            },
        ];
        for (test_index, test_vector) in test_vectors.iter().enumerate() {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(
                Some(test_vector.host),
                uri.host_to_string().unwrap().as_deref()
            );
            assert_eq!(
                test_vector.query,
                uri.query_to_string().unwrap().as_deref(),
                "{}",
                test_index
            );
            assert_eq!(
                test_vector.fragment,
                uri.fragment_to_string().unwrap().as_deref()
            );
        }
    }

    #[test]
    fn scheme_illegal_characters() {
        let test_vectors = [
            "://www.example.com/",
            "0://www.example.com/",
            "+://www.example.com/",
            "@://www.example.com/",
            ".://www.example.com/",
            "h@://www.example.com/",
        ];
        for test_vector in &test_vectors {
            let uri = Uri::parse(*test_vector);
            assert!(uri.is_err());
        }
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn scheme_barely_legal() {
        struct Test {
            uri_string: &'static str,
            scheme: &'static str,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "h://www.example.com/",
                scheme: "h",
            },
            Test {
                uri_string: "x+://www.example.com/",
                scheme: "x+",
            },
            Test {
                uri_string: "y-://www.example.com/",
                scheme: "y-",
            },
            Test {
                uri_string: "z.://www.example.com/",
                scheme: "z.",
            },
            Test {
                uri_string: "aa://www.example.com/",
                scheme: "aa",
            },
            Test {
                uri_string: "a0://www.example.com/",
                scheme: "a0",
            },
        ];
        for test_vector in test_vectors {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(Some(test_vector.scheme), uri.scheme());
        }
    }

    #[test]
    fn scheme_mixed_case() {
        let test_vectors = [
            "http://www.example.com/",
            "hTtp://www.example.com/",
            "HTTP://www.example.com/",
            "Http://www.example.com/",
            "HttP://www.example.com/",
        ];
        for test_vector in &test_vectors {
            let uri = Uri::parse(test_vector);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(Some("http"), uri.scheme());
        }
    }

    #[test]
    fn dont_misinterpret_colon_in_other_places_as_scheme_delimiter() {
        let test_vectors = [
            "//foo:bar@www.example.com/",
            "//www.example.com/a:b",
            "//www.example.com/foo?a:b",
            "//www.example.com/foo#a:b",
            "//[v7.:]/",
            "/:/foo",
        ];
        for test_vector in &test_vectors {
            let uri = Uri::parse(test_vector);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(None, uri.scheme());
        }
    }

    #[test]
    fn path_illegal_characters() {
        let test_vectors = [
            "http://www.example.com/foo[bar",
            "http://www.example.com/]bar",
            "http://www.example.com/foo]",
            "http://www.example.com/[",
            "http://www.example.com/abc/foo]",
            "http://www.example.com/abc/[",
            "http://www.example.com/foo]/abc",
            "http://www.example.com/[/abc",
            "http://www.example.com/foo]/",
            "http://www.example.com/[/",
            "/foo[bar",
            "/]bar",
            "/foo]",
            "/[",
            "/abc/foo]",
            "/abc/[",
            "/foo]/abc",
            "/[/abc",
            "/foo]/",
            "/[/",
        ];
        for test_vector in &test_vectors {
            let uri = Uri::parse(test_vector);
            assert!(uri.is_err());
        }
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn path_barely_legal() {
        struct Test {
            uri_string: &'static str,
            path: Vec<&'static [u8]>,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "/:/foo",
                path: vec![&b""[..], &b":"[..], &b"foo"[..]],
            },
            Test {
                uri_string: "bob@/foo",
                path: vec![&b"bob@"[..], &b"foo"[..]],
            },
            Test {
                uri_string: "hello!",
                path: vec![&b"hello!"[..]],
            },
            Test {
                uri_string: "urn:hello,%20w%6Frld",
                path: vec![&b"hello, world"[..]],
            },
            Test {
                uri_string: "//example.com/foo/(bar)/",
                path: vec![&b""[..], &b"foo"[..], &b"(bar)"[..], &b""[..]],
            },
        ];
        for test_vector in test_vectors {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(&test_vector.path, uri.path());
        }
    }

    #[test]
    fn query_illegal_characters() {
        let test_vectors = [
            "http://www.example.com/?foo[bar",
            "http://www.example.com/?]bar",
            "http://www.example.com/?foo]",
            "http://www.example.com/?[",
            "http://www.example.com/?abc/foo]",
            "http://www.example.com/?abc/[",
            "http://www.example.com/?foo]/abc",
            "http://www.example.com/?[/abc",
            "http://www.example.com/?foo]/",
            "http://www.example.com/?[/",
            "?foo[bar",
            "?]bar",
            "?foo]",
            "?[",
            "?abc/foo]",
            "?abc/[",
            "?foo]/abc",
            "?[/abc",
            "?foo]/",
            "?[/",
        ];
        for test_vector in &test_vectors {
            let uri = Uri::parse(test_vector);
            assert!(uri.is_err());
        }
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn query_barely_legal() {
        struct Test {
            uri_string: &'static str,
            query: &'static str,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "/?:/foo",
                query: ":/foo",
            },
            Test {
                uri_string: "?bob@/foo",
                query: "bob@/foo",
            },
            Test {
                uri_string: "?hello!",
                query: "hello!",
            },
            Test {
                uri_string: "urn:?hello,%20w%6Frld",
                query: "hello, world",
            },
            Test {
                uri_string: "//example.com/foo?(bar)/",
                query: "(bar)/",
            },
            Test {
                uri_string: "http://www.example.com/?foo?bar",
                query: "foo?bar",
            },
        ];
        for (test_index, test_vector) in test_vectors.iter().enumerate() {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(
                Some(test_vector.query),
                uri.query_to_string().unwrap().as_deref(),
                "{}",
                test_index
            );
        }
    }

    #[test]
    fn fragment_illegal_characters() {
        let test_vectors = [
            "http://www.example.com/#foo[bar",
            "http://www.example.com/#]bar",
            "http://www.example.com/#foo]",
            "http://www.example.com/#[",
            "http://www.example.com/#abc/foo]",
            "http://www.example.com/#abc/[",
            "http://www.example.com/#foo]/abc",
            "http://www.example.com/#[/abc",
            "http://www.example.com/#foo]/",
            "http://www.example.com/#[/",
            "#foo[bar",
            "#]bar",
            "#foo]",
            "#[",
            "#abc/foo]",
            "#abc/[",
            "#foo]/abc",
            "#[/abc",
            "#foo]/",
            "#[/",
        ];
        for test_vector in &test_vectors {
            let uri = Uri::parse(test_vector);
            assert!(uri.is_err());
        }
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn fragment_barely_legal() {
        struct Test {
            uri_string: &'static str,
            fragment: &'static str,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "/#:/foo",
                fragment: ":/foo",
            },
            Test {
                uri_string: "#bob@/foo",
                fragment: "bob@/foo",
            },
            Test {
                uri_string: "#hello!",
                fragment: "hello!",
            },
            Test {
                uri_string: "urn:#hello,%20w%6Frld",
                fragment: "hello, world",
            },
            Test {
                uri_string: "//example.com/foo#(bar)/",
                fragment: "(bar)/",
            },
            Test {
                uri_string: "http://www.example.com/#foo?bar",
                fragment: "foo?bar",
            },
        ];
        for test_vector in test_vectors {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(
                Some(test_vector.fragment),
                uri.fragment_to_string().unwrap().as_deref()
            );
        }
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn paths_with_percent_encoded_characters() {
        struct Test {
            uri_string: &'static str,
            path_first_segment: &'static [u8],
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "%41",
                path_first_segment: &b"A"[..],
            },
            Test {
                uri_string: "%4A",
                path_first_segment: &b"J"[..],
            },
            Test {
                uri_string: "%4a",
                path_first_segment: &b"J"[..],
            },
            Test {
                uri_string: "%bc",
                path_first_segment: &b"\xBC"[..],
            },
            Test {
                uri_string: "%Bc",
                path_first_segment: &b"\xBC"[..],
            },
            Test {
                uri_string: "%bC",
                path_first_segment: &b"\xBC"[..],
            },
            Test {
                uri_string: "%BC",
                path_first_segment: &b"\xBC"[..],
            },
            Test {
                uri_string: "%41%42%43",
                path_first_segment: &b"ABC"[..],
            },
            Test {
                uri_string: "%41%4A%43%4b",
                path_first_segment: &b"AJCK"[..],
            },
        ];
        for test_vector in test_vectors {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let uri = uri.unwrap();
            assert_eq!(test_vector.path_first_segment, uri.path().first().unwrap());
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn normalize_path() {
        struct Test {
            uri_string: &'static str,
            normalized_path: &'static str,
        }
        let test_vectors: &[Test] = &[
            Test {
                uri_string: "/a/b/c/./../../g",
                normalized_path: "/a/g",
            },
            Test {
                uri_string: "mid/content=5/../6",
                normalized_path: "mid/6",
            },
            Test {
                uri_string: "http://example.com/a/../b",
                normalized_path: "/b",
            },
            Test {
                uri_string: "http://example.com/../b",
                normalized_path: "/b",
            },
            Test {
                uri_string: "http://example.com/a/../b/",
                normalized_path: "/b/",
            },
            Test {
                uri_string: "http://example.com/a/../../b",
                normalized_path: "/b",
            },
            Test {
                uri_string: "./a/b",
                normalized_path: "a/b",
            },
            Test {
                uri_string: "",
                normalized_path: "",
            },
            Test {
                uri_string: ".",
                normalized_path: "",
            },
            Test {
                uri_string: "./",
                normalized_path: "",
            },
            Test {
                uri_string: "..",
                normalized_path: "",
            },
            Test {
                uri_string: "../",
                normalized_path: "",
            },
            Test {
                uri_string: "/",
                normalized_path: "/",
            },
            Test {
                uri_string: "a/b/..",
                normalized_path: "a/",
            },
            Test {
                uri_string: "a/b/../",
                normalized_path: "a/",
            },
            Test {
                uri_string: "a/b/.",
                normalized_path: "a/b/",
            },
            Test {
                uri_string: "a/b/./",
                normalized_path: "a/b/",
            },
            Test {
                uri_string: "a/b/./c",
                normalized_path: "a/b/c",
            },
            Test {
                uri_string: "a/b/./c/",
                normalized_path: "a/b/c/",
            },
            Test {
                uri_string: "/a/b/..",
                normalized_path: "/a/",
            },
            Test {
                uri_string: "/a/b/.",
                normalized_path: "/a/b/",
            },
            Test {
                uri_string: "/a/b/./c",
                normalized_path: "/a/b/c",
            },
            Test {
                uri_string: "/a/b/./c/",
                normalized_path: "/a/b/c/",
            },
            Test {
                uri_string: "./a/b/..",
                normalized_path: "a/",
            },
            Test {
                uri_string: "./a/b/.",
                normalized_path: "a/b/",
            },
            Test {
                uri_string: "./a/b/./c",
                normalized_path: "a/b/c",
            },
            Test {
                uri_string: "./a/b/./c/",
                normalized_path: "a/b/c/",
            },
            Test {
                uri_string: "../a/b/..",
                normalized_path: "a/",
            },
            Test {
                uri_string: "../a/b/.",
                normalized_path: "a/b/",
            },
            Test {
                uri_string: "../a/b/./c",
                normalized_path: "a/b/c",
            },
            Test {
                uri_string: "../a/b/./c/",
                normalized_path: "a/b/c/",
            },
            Test {
                uri_string: "../a/b/../c",
                normalized_path: "a/c",
            },
            Test {
                uri_string: "../a/b/./../c/",
                normalized_path: "a/c/",
            },
            Test {
                uri_string: "../a/b/./../c",
                normalized_path: "a/c",
            },
            Test {
                uri_string: "../a/b/./../c/",
                normalized_path: "a/c/",
            },
            Test {
                uri_string: "../a/b/.././c/",
                normalized_path: "a/c/",
            },
            Test {
                uri_string: "../a/b/.././c",
                normalized_path: "a/c",
            },
            Test {
                uri_string: "../a/b/.././c/",
                normalized_path: "a/c/",
            },
            Test {
                uri_string: "/./c/d",
                normalized_path: "/c/d",
            },
            Test {
                uri_string: "/../c/d",
                normalized_path: "/c/d",
            },
        ];
        for test_vector in test_vectors.iter() {
            let uri = Uri::parse(test_vector.uri_string);
            assert!(uri.is_ok());
            let mut uri = uri.unwrap();
            uri.normalize();
            assert_eq!(
                *test_vector.normalized_path,
                uri.path_to_string().unwrap(),
                "{}",
                test_vector.uri_string
            );
        }
    }

    #[test]
    fn construct_normalize_and_compare_equivalent_uris() {
        // This was inspired by section 6.2.2
        // of RFC 3986 (https://tools.ietf.org/html/rfc3986).
        let uri1 = Uri::parse("example://a/b/c/%7Bfoo%7D");
        assert!(uri1.is_ok());
        let uri1 = uri1.unwrap();
        let uri2 = Uri::parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d");
        assert!(uri2.is_ok());

        let mut uri2 = uri2.unwrap();
        assert_ne!(uri1, uri2, "\"example://a/b/c/%7Bfoo%7D\" and \"eXAMPLE://a/./b/../b/%63/%7bfoo%7d\" should not be equal");

        dbg!(&uri1);
        dbg!(&uri2);

        uri2.normalize();
        assert_eq!(uri1, uri2);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reference_resolution() {
        struct Test {
            base_string: &'static str,
            relative_reference_string: &'static str,
            target_string: &'static str,
        }
        let test_vectors: &[Test] = &[
            // These are all taken from section 5.4.1
            // of RFC 3986 (https://tools.ietf.org/html/rfc3986).
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g:h",
                target_string: "g:h",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g",
                target_string: "http://a/b/c/g",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "./g",
                target_string: "http://a/b/c/g",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g/",
                target_string: "http://a/b/c/g/",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "//g",
                target_string: "http://g",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "?y",
                target_string: "http://a/b/c/d;p?y",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g?y",
                target_string: "http://a/b/c/g?y",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "#s",
                target_string: "http://a/b/c/d;p?q#s",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g#s",
                target_string: "http://a/b/c/g#s",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g?y#s",
                target_string: "http://a/b/c/g?y#s",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: ";x",
                target_string: "http://a/b/c/;x",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g;x",
                target_string: "http://a/b/c/g;x",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "g;x?y#s",
                target_string: "http://a/b/c/g;x?y#s",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "",
                target_string: "http://a/b/c/d;p?q",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: ".",
                target_string: "http://a/b/c/",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "./",
                target_string: "http://a/b/c/",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "..",
                target_string: "http://a/b/",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "../",
                target_string: "http://a/b/",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "../g",
                target_string: "http://a/b/g",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "../..",
                target_string: "http://a",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "../../",
                target_string: "http://a",
            },
            Test {
                base_string: "http://a/b/c/d;p?q",
                relative_reference_string: "../../g",
                target_string: "http://a/g",
            },
            Test {
                base_string: "foo",
                relative_reference_string: "bar",
                target_string: "bar",
            },
            Test {
                base_string: "http://example.com",
                relative_reference_string: "foo",
                target_string: "http://example.com/foo",
            },
            Test {
                base_string: "http://example.com/",
                relative_reference_string: "foo",
                target_string: "http://example.com/foo",
            },
            Test {
                base_string: "http://example.com",
                relative_reference_string: "foo/",
                target_string: "http://example.com/foo/",
            },
            Test {
                base_string: "http://example.com/",
                relative_reference_string: "foo/",
                target_string: "http://example.com/foo/",
            },
            Test {
                base_string: "http://example.com",
                relative_reference_string: "/foo",
                target_string: "http://example.com/foo",
            },
            Test {
                base_string: "http://example.com/",
                relative_reference_string: "/foo",
                target_string: "http://example.com/foo",
            },
            Test {
                base_string: "http://example.com",
                relative_reference_string: "/foo/",
                target_string: "http://example.com/foo/",
            },
            Test {
                base_string: "http://example.com/",
                relative_reference_string: "/foo/",
                target_string: "http://example.com/foo/",
            },
            Test {
                base_string: "http://example.com/",
                relative_reference_string: "?foo",
                target_string: "http://example.com/?foo",
            },
            Test {
                base_string: "http://example.com/",
                relative_reference_string: "#foo",
                target_string: "http://example.com/#foo",
            },
        ];
        for test_vector in test_vectors {
            let base_uri = Uri::parse(test_vector.base_string).unwrap();
            let relative_reference_uri = Uri::parse(test_vector.relative_reference_string).unwrap();
            let expected_target_uri = Uri::parse(test_vector.target_string).unwrap();
            let actual_target_uri = dbg!(base_uri.resolve(&relative_reference_uri));
            assert_eq!(expected_target_uri, actual_target_uri);
        }
    }

    #[test]
    fn empty_path_in_uri_with_authority_is_equivalent_to_slash_only_path() {
        let uri1 = Uri::parse("http://example.com");
        assert!(uri1.is_ok());

        let uri1 = uri1.unwrap();
        let uri2 = Uri::parse("http://example.com/");

        assert!(uri2.is_ok());
        let uri2 = uri2.unwrap();

        assert_eq!(uri1, uri2, "uri1 and uri2 should be equivalent");

        let uri1 = Uri::parse("//example.com");
        assert!(uri1.is_ok());

        let uri1 = uri1.unwrap();
        let uri2 = Uri::parse("//example.com/");
        assert!(uri2.is_ok());

        let uri2 = uri2.unwrap();
        assert_eq!(uri1, uri2);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generate_string() {
        struct Test {
            scheme: Option<&'static str>,
            user_info: Option<&'static str>,
            host: Option<&'static str>,
            port: Option<u16>,
            path: &'static str,
            query: Option<&'static str>,
            fragment: Option<&'static str>,
            expected_uri_string: &'static str,
        }
        // #[rustfmt::skip]
        let test_vectors: &[Test] = &[
            // general test vectors
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.example.com"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foobar"),
                fragment: Some("ch2"),
                expected_uri_string: "http://bob@www.example.com:8080/abc/def?foobar#ch2",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.example.com"),
                port: Some(0),
                path: "",
                query: Some("foobar"),
                fragment: Some("ch2"),
                expected_uri_string: "http://bob@www.example.com:0?foobar#ch2",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.example.com"),
                port: Some(0),
                path: "",
                query: Some("foobar"),
                fragment: Some(""),
                expected_uri_string: "http://bob@www.example.com:0?foobar#",
            },
            Test {
                scheme: None,
                user_info: None,
                host: Some("example.com"),
                port: None,
                path: "",
                query: Some("bar"),
                fragment: None,
                expected_uri_string: "//example.com?bar",
            },
            Test {
                scheme: None,
                user_info: None,
                host: Some("example.com"),
                port: None,
                path: "",
                query: Some(""),
                fragment: None,
                expected_uri_string: "//example.com?",
            },
            Test {
                scheme: None,
                user_info: None,
                host: Some("example.com"),
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "//example.com",
            },
            Test {
                scheme: None,
                user_info: None,
                host: Some("example.com"),
                port: None,
                path: "/",
                query: None,
                fragment: None,
                expected_uri_string: "//example.com/",
            },
            Test {
                scheme: None,
                user_info: None,
                host: Some("example.com"),
                port: None,
                path: "/xyz",
                query: None,
                fragment: None,
                expected_uri_string: "//example.com/xyz",
            },
            Test {
                scheme: None,
                user_info: None,
                host: Some("example.com"),
                port: None,
                path: "/xyz/",
                query: None,
                fragment: None,
                expected_uri_string: "//example.com/xyz/",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "/",
                query: None,
                fragment: None,
                expected_uri_string: "/",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "/xyz",
                query: None,
                fragment: None,
                expected_uri_string: "/xyz",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "/xyz/",
                query: None,
                fragment: None,
                expected_uri_string: "/xyz/",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "xyz",
                query: None,
                fragment: None,
                expected_uri_string: "xyz",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "xyz/",
                query: None,
                fragment: None,
                expected_uri_string: "xyz/",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "",
                query: Some("bar"),
                fragment: None,
                expected_uri_string: "?bar",
            },
            Test {
                scheme: Some("http"),
                user_info: None,
                host: None,
                port: None,
                path: "",
                query: Some("bar"),
                fragment: None,
                expected_uri_string: "http:?bar",
            },
            Test {
                scheme: Some("http"),
                user_info: None,
                host: None,
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "http:",
            },
            Test {
                scheme: Some("http"),
                user_info: None,
                host: Some("::1"),
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "http://[::1]",
            },
            Test {
                scheme: Some("http"),
                user_info: None,
                host: Some("::1.2.3.4"),
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "http://[::1.2.3.4]",
            },
            Test {
                scheme: Some("http"),
                user_info: None,
                host: Some("1.2.3.4"),
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "http://1.2.3.4",
            },
            Test {
                scheme: None,
                user_info: None,
                host: None,
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: None,
                port: None,
                path: "",
                query: Some("foobar"),
                fragment: None,
                expected_uri_string: "http://bob@?foobar",
            },
            Test {
                scheme: None,
                user_info: Some("bob"),
                host: None,
                port: None,
                path: "",
                query: Some("foobar"),
                fragment: None,
                expected_uri_string: "//bob@?foobar",
            },
            Test {
                scheme: None,
                user_info: Some("bob"),
                host: None,
                port: None,
                path: "",
                query: None,
                fragment: None,
                expected_uri_string: "//bob@",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("b b"),
                host: Some("www.example.com"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foobar"),
                fragment: Some("ch2"),
                expected_uri_string: "http://b%20b@www.example.com:8080/abc/def?foobar#ch2",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.e ample.com"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foobar"),
                fragment: Some("ch2"),
                expected_uri_string: "http://bob@www.e%20ample.com:8080/abc/def?foobar#ch2",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.example.com"),
                port: Some(8080),
                path: "/a c/def",
                query: Some("foobar"),
                fragment: Some("ch2"),
                expected_uri_string: "http://bob@www.example.com:8080/a%20c/def?foobar#ch2",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.example.com"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foo ar"),
                fragment: Some("ch2"),
                expected_uri_string: "http://bob@www.example.com:8080/abc/def?foo%20ar#ch2",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("www.example.com"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foobar"),
                fragment: Some("c 2"),
                expected_uri_string: "http://bob@www.example.com:8080/abc/def?foobar#c%202",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("ሴ.example.com"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foobar"),
                fragment: None,
                expected_uri_string: "http://bob@%E1%88%B4.example.com:8080/abc/def?foobar",
            },
            Test {
                scheme: Some("http"),
                user_info: Some("bob"),
                host: Some("fFfF::1"),
                port: Some(8080),
                path: "/abc/def",
                query: Some("foobar"),
                fragment: Some("c 2"),
                expected_uri_string: "http://bob@[ffff::1]:8080/abc/def?foobar#c%202",
            },
        ];
        for test_vector in test_vectors {
            let mut uri = Uri::default();
            assert!(uri
                .set_scheme(test_vector.scheme.map(ToString::to_string))
                .is_ok());
            if test_vector.user_info.is_some()
                || test_vector.host.is_some()
                || test_vector.port.is_some()
            {
                let mut authority = Authority::default();
                authority.set_user_info(test_vector.user_info.map(Into::into));
                authority.set_host(test_vector.host.unwrap_or(""));
                authority.set_port(test_vector.port);
                uri.set_authority(Some(authority));
            } else {
                uri.set_authority(None);
            }
            uri.set_path_from_str(test_vector.path);
            uri.set_query(test_vector.query.map(Into::into));
            uri.set_fragment(test_vector.fragment.map(Into::into));
            assert_eq!(*test_vector.expected_uri_string, uri.to_string());
        }
    }

    #[test]
    fn fragment_empty_but_present() {
        let uri = Uri::parse("http://example.com#");
        assert!(uri.is_ok());
        let mut uri = uri.unwrap();
        assert_eq!(Some(&b""[..]), uri.fragment());
        assert_eq!(uri.to_string(), "http://example.com/#");
        uri.set_fragment(None);
        assert_eq!(uri.to_string(), "http://example.com/");
        assert_eq!(None, uri.fragment());

        let uri = Uri::parse("http://example.com");
        assert!(uri.is_ok());
        let mut uri = uri.unwrap();
        assert_eq!(None, uri.fragment());
        uri.set_fragment(Some(vec![]));
        assert_eq!(Some(&b""[..]), uri.fragment());
        assert_eq!(uri.to_string(), "http://example.com/#");
    }

    #[test]
    fn query_empty_but_present() {
        let uri = Uri::parse("http://example.com?");
        assert!(uri.is_ok());
        let mut uri = uri.unwrap();
        assert_eq!(Some(&b""[..]), uri.query());
        assert_eq!(uri.to_string(), "http://example.com/?");
        uri.set_query(None);
        assert_eq!(uri.to_string(), "http://example.com/");
        assert_eq!(None, uri.query());

        let uri = Uri::parse("http://example.com");
        assert!(uri.is_ok());
        let mut uri = uri.unwrap();
        assert_eq!(None, uri.query());
        uri.set_query(Some(vec![]));
        assert_eq!(Some(&b""[..]), uri.query());
        assert_eq!(uri.to_string(), "http://example.com/?");
    }

    #[test]
    fn make_a_copy() {
        let mut uri1 = Uri::parse("http://www.example.com/foo.txt").unwrap();
        let mut uri2 = uri1.clone();
        uri1.set_query(Some(b"bar".to_vec()));
        uri2.set_fragment(Some(b"page2".to_vec()));
        let mut uri2_new_auth = uri2.authority().unwrap().clone();
        uri2_new_auth.set_host("example.com");
        uri2.set_authority(Some(uri2_new_auth));
        assert_eq!(uri1.to_string(), "http://www.example.com/foo.txt?bar");
        assert_eq!(uri2.to_string(), "http://example.com/foo.txt#page2");
    }

    #[test]
    fn clear_query() {
        let mut uri = Uri::parse("http://www.example.com/?foo=bar").unwrap();
        uri.set_query(None);
        assert_eq!(uri.to_string(), "http://www.example.com/");
        assert_eq!(None, uri.query());
    }

    #[test]
    fn percent_encode_plus_in_queries() {
        // Although RFC 3986 doesn't say anything about '+', some web services
        // treat it the same as ' ' due to how HTML originally defined how
        // to encode the query portion of a URL
        // (see https://stackoverflow.com/questions/2678551/when-to-encode-space-to-plus-or-20).
        //
        // To avoid issues with these web services, make sure '+' is
        // percent-encoded in a URI when the URI is encoded.
        let mut uri = Uri::default();
        uri.set_query(Some(b"foo+bar".to_vec()));
        assert_eq!(uri.to_string(), "?foo%2Bbar");
    }

    #[test]
    fn percent_encode_characters_with_two_digits_always() {
        for ci in 0_u8..31_u8 {
            let mut uri = Uri::default();
            uri.set_query(Some(vec![ci]));
            assert_eq!(uri.to_string(), format!("?%{:02X}", ci));
        }
    }

    #[test]
    fn set_illegal_schemes() {
        let test_vectors = ["ab_de", "ab/de", "ab:de", "", "&", "foo&bar"];
        for test_vector in &test_vectors {
            let mut uri = Uri::default();
            assert!(uri.set_scheme(Some((*test_vector).to_string())).is_err());
        }
    }

    // #[test]
    // fn take_parts() {
    //     let mut uri = Uri::parse("https://www.example.com/foo?bar#baz").unwrap();
    //     assert_eq!(Some("https"), uri.take_scheme().as_deref());
    //     assert_eq!("//www.example.com/foo?bar#baz", uri.to_string());
    //     assert!(matches!(
    //         uri.take_authority(),
    //         Some(authority) if authority.host() == b"www.example.com"
    //     ));
    //     assert_eq!("/foo?bar#baz", uri.to_string());
    //     assert!(matches!(uri.take_authority(), None));
    //     assert_eq!(Some(&b"bar"[..]), uri.take_query().as_deref());
    //     assert_eq!("/foo#baz", uri.to_string());
    //     assert_eq!(None, uri.take_query().as_deref());
    //     assert_eq!(Some(&b"baz"[..]), uri.take_fragment().as_deref());
    //     assert_eq!("/foo", uri.to_string());
    //     assert_eq!(None, uri.take_fragment().as_deref());
    // }
}
