#![warn(clippy::pedantic)]

use super::{character_classes::DIGIT, context::Context, error::Error};

struct Shared {
    num_groups: usize,
    octet_buffer: String,
}

enum State {
    NotInOctet(Shared),
    ExpectDigitOrDot(Shared),
}

impl State {
    fn finalize(self) -> Result<(), Error> {
        match self {
            Self::NotInOctet(_) => Err(Error::TruncatedHost),
            Self::ExpectDigitOrDot(state) => Self::finalize_expect_digit_or_dot(state),
        }
    }

    fn finalize_expect_digit_or_dot(state: Shared) -> Result<(), Error> {
        let mut state = state;
        if !state.octet_buffer.is_empty() {
            state.num_groups += 1;
            if state.octet_buffer.parse::<u8>().is_err() {
                return Err(Error::InvalidDecimalOctet);
            }
        }
        match state.num_groups {
            4 => Ok(()),
            n if n < 4 => Err(Error::TooFewAddressParts),
            _ => Err(Error::TooManyAddressParts),
        }
    }

    fn new() -> Self {
        Self::NotInOctet(Shared {
            num_groups: 0,
            octet_buffer: String::new(),
        })
    }

    fn next(self, c: char) -> Result<Self, Error> {
        match self {
            Self::NotInOctet(state) => Self::next_not_in_octet(state, c),
            Self::ExpectDigitOrDot(state) => Self::next_expect_digit_or_dot(state, c),
        }
    }

    fn next_not_in_octet(state: Shared, c: char) -> Result<Self, Error> {
        let mut state = state;
        if DIGIT.contains(&c) {
            state.octet_buffer.push(c);
            Ok(Self::ExpectDigitOrDot(state))
        } else {
            Err(Error::IllegalCharacter(Context::Ipv4Address))
        }
    }

    fn next_expect_digit_or_dot(state: Shared, c: char) -> Result<Self, Error> {
        let mut state = state;
        if c == '.' {
            state.num_groups += 1;
            if state.num_groups > 4 {
                return Err(Error::TooManyAddressParts);
            }
            if state.octet_buffer.parse::<u8>().is_err() {
                return Err(Error::InvalidDecimalOctet);
            }
            state.octet_buffer.clear();
            Ok(Self::NotInOctet(state))
        } else if DIGIT.contains(&c) {
            state.octet_buffer.push(c);
            Ok(Self::ExpectDigitOrDot(state))
        } else {
            Err(Error::IllegalCharacter(Context::Ipv4Address))
        }
    }
}

pub fn validate_ipv4_address<T>(address: T) -> Result<(), Error>
where
    T: AsRef<str>,
{
    address
        .as_ref()
        .chars()
        .try_fold(State::new(), State::next)?
        .finalize()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn good() {
        let test_vectors = [
            "0.0.0.0",
            "1.2.3.0",
            "1.2.3.4",
            "1.2.3.255",
            "1.2.255.4",
            "1.255.3.4",
            "255.2.3.4",
            "255.255.255.255",
        ];
        for test_vector in &test_vectors {
            assert!(validate_ipv4_address(*test_vector).is_ok());
        }
    }

    #[test]
    fn bad() {
        struct Test {
            addr: &'static str,
            expected: Error,
        }
        let test_vectors: &[Test] = &[
            Test {
                addr: "1.2.x.4",
                expected: Error::IllegalCharacter(Context::Ipv4Address),
            },
            Test {
                addr: "1.2.3.4.8",
                expected: Error::TooManyAddressParts,
            },
            Test {
                addr: "1.2.3",
                expected: Error::TooFewAddressParts,
            },
            Test {
                addr: "1.2.3.",
                expected: Error::TruncatedHost,
            },
            Test {
                addr: "1.2.3.256",
                expected: Error::InvalidDecimalOctet,
            },
            Test {
                addr: "1.2.3.-4",
                expected: Error::IllegalCharacter(Context::Ipv4Address),
            },
            Test {
                addr: "1.2.3. 4",
                expected: Error::IllegalCharacter(Context::Ipv4Address),
            },
            Test {
                addr: "1.2.3.4 ",
                expected: Error::IllegalCharacter(Context::Ipv4Address),
            },
        ];
        for test_vector in test_vectors {
            let result = validate_ipv4_address(test_vector.addr);
            assert!(result.is_err(), "{}", test_vector.addr);
            assert_eq!(
                test_vector.expected,
                result.unwrap_err(),
                "{}",
                test_vector.addr
            );
        }
    }
}
