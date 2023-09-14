use std::{borrow::Borrow, ops::Deref, string::FromUtf8Error};

use crate::{error::MissingSchemeError, Authority, Error, Uri};

/// An absolute [`Uri`]
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AbsoluteUri {
    pub(crate) uri: Uri,
}

impl AbsoluteUri {
    /// Returns the `Uri` representation of this `AbsoluteUri`.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Borrow the authority (if any) of the URI.
    #[must_use = "authority not used"]
    pub fn authority(&self) -> Option<Authority> {
        self.uri.authority()
    }

    /// Borrow the fragment (if any) of the URI.
    #[must_use]
    pub fn fragment(&self) -> Option<Vec<u8>> {
        self.uri.fragment()
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
        self.uri.fragment_to_string()
    }

    /// Borrow the host portion of the Authority (if any) of the URI.
    #[must_use]
    pub fn host(&self) -> Option<Vec<u8>> {
        self.uri.host()
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
        self.uri.host_to_string()
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
        self.uri.normalize()
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
        Uri::parse(uri_string.as_ref())?.try_into()
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
        self.uri.path()
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
        self.uri.path_to_string()
    }

    /// Return a copy of the port (if any) contained in the URI.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.uri.port()
    }

    /// Borrow the query (if any) of the URI.
    #[must_use]
    pub fn query(&self) -> Option<Vec<u8>> {
        self.uri.query()
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
        self.uri.query_to_string()
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
    pub fn resolve(&self, relative_reference: impl Borrow<Uri>) -> Self {
        // the unwrap bel
        self.uri
            .resolve(relative_reference.borrow())
            .try_into()
            .expect("failed to convert resolved Uri to AbsoluteUri. This is a bug. Please report it to https://github.com/chanced/uniresid/issues")
    }

    /// Borrow the scheme (if any) component of the URI.
    #[must_use]
    pub fn scheme(&self) -> &str {
        // NOTE: This seemingly magic `as_deref` works because of two
        // things that are going on here:
        // 1) String implements DeRef with `str` as the associated type
        //    `Target`, meaning you can use a String in a context requiring
        //    &str, and String does the conversion work.
        // 2) as_deref works by turning `Option<T>` into `Option<&T::Target>`,
        //    requiring T to implement Deref.  In this case T is String.
        self.uri.scheme().expect("Absolute URI did not contain a scheme. This is a bug. Please report it to https://github.com/chanced/uniresid/issues")
    }

    /// Change the authority of the URI.
    pub fn set_authority<T>(&mut self, authority: T)
    where
        T: Into<Option<Authority>>,
    {
        self.uri.set_authority(authority);
    }

    /// Change the fragment of the URI.
    pub fn set_fragment<T>(&mut self, fragment: T)
    where
        T: Into<Option<Vec<u8>>>,
    {
        self.uri.set_fragment(fragment);
    }

    /// Change the path of the URI.
    ///
    /// Note: See [`path`](#method.path) for special notes about what the
    /// segments of the path mean.
    pub fn set_path<T>(&mut self, path: T)
    where
        T: Into<Vec<Vec<u8>>>,
    {
        self.uri.set_path(path);
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
        self.uri.set_path_from_str(path);
    }

    /// Change the query of the URI.
    pub fn set_query<T>(&mut self, query: T)
    where
        T: Into<Option<Vec<u8>>>,
    {
        self.uri.set_query(query);
    }

    /// Change the scheme of the URI.
    ///
    /// # Errors
    ///
    /// The set of characters allowed in the scheme of a URI is limited.
    /// [`Error::IllegalCharacter`](enum.Error.html#variant.IllegalCharacter)
    /// is returned if you try to use a character that isn't allowed.
    pub fn set_scheme<T>(&mut self, scheme: &str) -> Result<(), Error> {
        if scheme.is_empty() {
            Err(Error::EmptyScheme)
        } else {
            self.uri.set_scheme(Some(scheme.to_string()))
        }
    }

    // /// Remove and return the authority portion (if any) of the URI.
    // #[must_use]
    // pub fn take_authority(&mut self) -> Option<Authority> {
    //     self.uri.take_authority()
    // }

    // /// Remove and return the fragment portion (if any) of the URI.
    // #[must_use]
    // pub fn take_fragment(&mut self) -> Option<Vec<u8>> {
    //     self.uri.take_fragment()
    // }

    // /// Remove and return the query portion (if any) of the URI.
    // #[must_use]
    // pub fn take_query(&mut self) -> Option<Vec<u8>> {
    //     self.uri.take_query()
    // }

    /// Borrow the `user_info` portion (if any) of the Authority (if any) of the
    /// URI.
    ///
    /// Note that you can get `None` if there is either no Authority in the URI
    /// or there is an Authority in the URI but it has no `user_info` in it.
    #[must_use]
    pub fn user_info(&self) -> Option<&[u8]> {
        self.uri.user_info()
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
}

impl TryFrom<Uri> for AbsoluteUri {
    type Error = Error;
    fn try_from(uri: Uri) -> Result<Self, Self::Error> {
        if uri.scheme().is_none() {
            Err(MissingSchemeError {
                uri_string: uri.to_string(),
            }
            .into())
        } else {
            Ok(Self { uri })
        }
    }
}
impl Borrow<Uri> for AbsoluteUri {
    fn borrow(&self) -> &Uri {
        &self.uri
    }
}

impl Deref for AbsoluteUri {
    type Target = Uri;
    fn deref(&self) -> &Self::Target {
        &self.uri
    }
}
#[cfg(feature = "url")]
impl TryInto<AbsoluteUri> for url_::Url {
    type Error = Error;

    fn try_into(self) -> Result<AbsoluteUri, Self::Error> {
        AbsoluteUri::parse(self)
    }
}

#[cfg(feature = "url")]
impl TryFrom<AbsoluteUri> for url_::Url {
    type Error = url_::ParseError;

    fn try_from(value: AbsoluteUri) -> Result<Self, Self::Error> {
        value.uri.try_into()
    }
}

#[cfg(feature = "serde")]
impl serde_::Serialize for AbsoluteUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde_::Serializer,
    {
        serializer.serialize_str(&self.uri)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde_::Deserialize<'de> for AbsoluteUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde_::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(s).map_err(serde_::de::Error::custom)
    }
}
impl std::fmt::Debug for AbsoluteUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AbsoluteUri")
            .field(&self.to_string())
            .finish()
    }
}
impl TryFrom<&'_ str> for AbsoluteUri {
    type Error = Error;

    fn try_from(uri_string: &'_ str) -> Result<Self, Self::Error> {
        AbsoluteUri::parse(uri_string)
    }
}

impl TryFrom<String> for AbsoluteUri {
    type Error = Error;

    fn try_from(uri_string: String) -> Result<Self, Self::Error> {
        AbsoluteUri::parse(uri_string)
    }
}
impl std::fmt::Display for AbsoluteUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.uri.to_string())
    }
}
