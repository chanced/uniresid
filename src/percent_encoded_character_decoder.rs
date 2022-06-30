use std::convert::TryFrom;

use super::error::Error;

pub struct PercentEncodedCharacterDecoder {
    decoded_character: u8,
    digits_left: usize,
}

impl PercentEncodedCharacterDecoder {
    pub fn new() -> Self {
        Self {
            decoded_character: 0,
            digits_left: 2,
        }
    }

    pub fn next(&mut self, c: char) -> Result<Option<u8>, Error> {
        self.shift_in_hex_digit(c)?;
        self.digits_left -= 1;
        if self.digits_left == 0 {
            let output = self.decoded_character;
            self.reset();
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }

    fn reset(&mut self) {
        self.decoded_character = 0;
        self.digits_left = 2;
    }

    fn shift_in_hex_digit(&mut self, c: char) -> Result<(), Error> {
        self.decoded_character <<= 4;
        if let Some(ci) = c.to_digit(16) {
            self.decoded_character += u8::try_from(ci).unwrap();
        } else {
            self.reset();
            return Err(Error::IllegalPercentEncoding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn good_sequences() {
        let test_vectors: &[([char; 2], u8)] = &[
            (['4', '1'], b'A'),
            (['5', 'A'], b'Z'),
            (['6', 'e'], b'n'),
            (['e', '1'], b'\xe1'),
            (['C', 'A'], b'\xca'),
        ];
        for test_vector in test_vectors {
            let mut pec = PercentEncodedCharacterDecoder::new();
            assert_eq!(Ok(None), pec.next(test_vector.0[0]));
            assert_eq!(Ok(Some(test_vector.1)), pec.next(test_vector.0[1]));
        }
    }

    #[test]
    fn bad_sequences() {
        let test_vectors = ['G', 'g', '.', 'z', '-', ' ', 'V'];
        for test_vector in &test_vectors {
            let mut pec = PercentEncodedCharacterDecoder::new();
            assert!(pec.next(*test_vector).is_err());
        }
    }
}
