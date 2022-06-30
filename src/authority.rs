use super::{
    character_classes::{REG_NAME_NOT_PCT_ENCODED, USER_INFO_NOT_PCT_ENCODED},
    codec::{decode_element, encode_element},
    context::Context,
    error::Error,
    parse_host_port::parse_host_port,
    validate_ipv6_address::validate_ipv6_address,
};

/// This is the optional part of a URI which governs the URI's namespace.  It
/// typically contains a host name or IP address, and may also include a port
/// number and/or `user_info` component.
///
/// # Examples
///
/// ## Parsing an Authority into its components
///
/// ```rust
/// use uniresid::Authority;
///
/// # fn main() -> Result<(), uniresid::Error> {
/// let authority = Authority::parse("nobody@www.example.com:8080")?;
/// assert_eq!(Some("nobody".as_bytes()), authority.user_info());
/// assert_eq!("www.example.com".as_bytes(), authority.host());
/// assert_eq!(Some(8080), authority.port());
/// # Ok(())
/// # }
/// ```
///
/// ## Generating a URI from its components
///
/// ```rust
/// use uniresid::Authority;
///
/// # fn main() -> Result<(), uniresid::Error> {
/// let mut authority = Authority::default();
/// authority.set_user_info(Some("nobody").map(Into::into));
/// authority.set_host("www.example.com");
/// authority.set_port(Some(8080));
/// assert_eq!("nobody@www.example.com:8080", authority.to_string());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Authority {
    user_info: Option<Vec<u8>>,
    host: Vec<u8>,
    port: Option<u16>,
}

impl Authority {
    /// Borrow the host name part of the Authority.
    #[must_use = "host not used"]
    pub fn host(&self) -> &[u8] {
        &self.host
    }

    /// Borrow the port number part of the Authority.
    #[must_use = "port not used"]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Change the `user_info` part of the Authority.
    pub fn set_user_info<T>(&mut self, user_info: T)
    where
        T: Into<Option<Vec<u8>>>,
    {
        self.user_info = user_info.into();
    }

    /// Change the host name part of the Authority.
    pub fn set_host<T>(&mut self, host: T)
    where
        T: Into<Vec<u8>>,
    {
        self.host = host.into();
    }

    /// Change the port number part of the Authority.
    pub fn set_port(&mut self, port: Option<u16>) {
        self.port = port;
    }

    /// Borrow the `user_info` part of the Authority.
    #[must_use = "user_info not used"]
    pub fn user_info(&self) -> Option<&[u8]> {
        self.user_info.as_deref()
    }

    /// Interpret the given string as the Authority component of a URI,
    /// separating its various subcomponents, returning an `Authority` value
    /// containing them.
    ///
    /// # Errors
    ///
    /// There are many ways to screw up the Authority part of URI string, and
    /// this function will let you know what's up by returning a variant of the
    /// [`Error`](enum.Error.html) type.
    pub fn parse<T>(authority_string: T) -> Result<Self, Error>
    where
        T: AsRef<str>,
    {
        let (user_info, host_port_string) = Self::parse_user_info(authority_string.as_ref())?;
        let (host, port) = parse_host_port(host_port_string)?;
        Ok(Self {
            user_info,
            host,
            port,
        })
    }

    fn parse_user_info(authority: &str) -> Result<(Option<Vec<u8>>, &str), Error> {
        Ok(match authority.find('@') {
            Some(delimiter) => (
                Some(decode_element(
                    &authority[0..delimiter],
                    &USER_INFO_NOT_PCT_ENCODED,
                    Context::UserInfo,
                )?),
                &authority[delimiter + 1..],
            ),
            None => (None, authority),
        })
    }
}

impl std::fmt::Display for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(user_info) = &self.user_info {
            write!(
                f,
                "{}@",
                encode_element(user_info, &USER_INFO_NOT_PCT_ENCODED)
            )?;
        }
        let host_to_string = String::from_utf8(self.host.clone());
        match host_to_string {
            Ok(host_to_string) if validate_ipv6_address(&host_to_string).is_ok() => {
                write!(f, "[{}]", host_to_string.to_ascii_lowercase())?;
            }
            _ => {
                write!(
                    f,
                    "{}",
                    encode_element(&self.host, &REG_NAME_NOT_PCT_ENCODED)
                )?;
            }
        }
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn user_info() {
        struct Test {
            auth: &'static str,
            user_info: Option<&'static str>,
        }
        let test_vectors: &[Test] = &[
            Test {
                auth: "www.example.com",
                user_info: None,
            },
            Test {
                auth: "joe@www.example.com",
                user_info: Some("joe"),
            },
            Test {
                auth: "pepe:feelsbadman@www.example.com",
                user_info: Some("pepe:feelsbadman"),
            },
        ];
        for test_vector in test_vectors {
            let authority = Authority::parse(test_vector.auth);
            assert!(authority.is_ok());
            let authority = authority.unwrap();
            assert_eq!(
                test_vector.user_info.map(str::as_bytes),
                authority.user_info.as_ref().map(|v| &v[..])
            );
        }
    }

    #[test]
    fn user_info_illegal_characters() {
        let test_vectors = ["%X@www.example.com", "{@www.example.com"];
        for test_vector in &test_vectors {
            let authority = Authority::parse(test_vector);
            assert!(authority.is_err());
        }
    }

    #[test]
    fn user_info_barely_legal() {
        let test_vectors: &[(&str, &str)] = &[
            ("%41@www.example.com", "A"),
            ("@www.example.com", ""),
            ("!@www.example.com", "!"),
            ("'@www.example.com", "'"),
            ("(@www.example.com", "("),
            (";@www.example.com", ";"),
            (":@www.example.com", ":"),
        ];
        for test_vector in test_vectors {
            let authority = Authority::parse(test_vector.0);
            assert!(authority.is_ok());
            let authority = authority.unwrap();
            assert_eq!(
                Some(test_vector.1.as_bytes()),
                authority.user_info.as_ref().map(|v| &v[..])
            );
        }
    }

    #[test]
    fn host_illegal_characters() {
        let test_vectors = ["%X@www.example.com", "@www:example.com", "[vX.:]"];
        for test_vector in &test_vectors {
            let authority = Authority::parse(test_vector);
            assert!(authority.is_err());
        }
    }

    #[test]
    #[allow(clippy::from_over_into)]
    fn host_barely_legal() {
        let test_vectors: &[(&str, &str)] = &[
            ("%41", "a"),
            ("", ""),
            ("!", "!"),
            ("'", "'"),
            ("(", "("),
            (";", ";"),
            ("1.2.3.4", "1.2.3.4"),
            ("[v7.:]", "v7.:"),
            ("[v7.aB]", "v7.aB"),
        ];
        for test_vector in test_vectors {
            let authority = Authority::parse(test_vector.0);
            assert!(authority.is_ok());
            let authority = authority.unwrap();
            assert_eq!(test_vector.1.as_bytes(), authority.host());
        }
    }

    #[test]
    fn host_ends_in_dot() {
        let authority = Authority::parse("example.com.");
        assert!(authority.is_ok());
        let authority = authority.unwrap();
        assert_eq!(b"example.com.", authority.host());
    }

    #[test]
    fn host_mixed_case() {
        let test_vectors = [
            "www.example.com",
            "www.EXAMPLE.com",
            "www.exAMple.com",
            "www.example.cOM",
            "wWw.exampLe.Com",
        ];
        let normalized_host = "www.example.com";
        for test_vector in &test_vectors {
            let authority = Authority::parse(*test_vector);
            assert!(authority.is_ok());
            let authority = authority.unwrap();
            assert_eq!(normalized_host.as_bytes(), authority.host());
        }
    }
}
