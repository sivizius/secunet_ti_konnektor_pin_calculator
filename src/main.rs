#![feature(array_try_from_fn)]
#![feature(array_try_map)]
#![feature(result_option_inspect)]

/// Set the number of card readers.
/// CARD_READERS and SERIAL_NUMBERS must have this many elements!
const NUMBER_OF_CARD_READERS: usize = 3;

/// Set the number of pins to calculate.
/// This value should be less than 16,
///    because the randomness buffer might not large enough.
const NUMBER_OF_PINS:         usize = 6;

/// Set the paths of card-reader devices.
const CARD_READERS: ListOfCardReaders
= [
    "/sys/bus/usb/devices/1-4/serial",
    "/sys/bus/usb/devices/1-5/serial",
    "/sys/bus/usb/devices/1-6/serial",
  ];

/// Set some serial numbers for testing purposes.
/// If None, the serial numbers will be read from the card-readers.
const SERIAL_NUMBERS: MaybeSerialNumbers
= Some([
    SerialNumber(*b"23421337"),
    SerialNumber(*b"meowmeow"),
    SerialNumber(*b"*squeak*"),
  ]);

use {
  core::{
    array::{
      self,
      IntoIter,
    },
    option::Option,
    result::Result,
  },
  sha2::{
    Digest,
    Sha512,
  },
  std::{
    fmt::{
      Display,
      Formatter,
      Result as FormatResult,
    },
    fs::File,
    io::Read,
  },
};

const SHA512_HASH_LENGTH: usize = 0x40;

type Error                = &'static str;
type ListOfCardReaders    = [&'static str; NUMBER_OF_CARD_READERS];
type ListOfPins           = [Pin; NUMBER_OF_PINS];
type ListOfSerialNumbers  = [SerialNumber; NUMBER_OF_CARD_READERS];
type MaybeSerialNumbers   = Option<ListOfSerialNumbers>;

#[allow(dead_code)]
#[derive(Debug)]
enum Algorithm {
  DefaultPin    = 0,
  DoubleSHA512  = 3,
}

#[derive(Clone, Copy, Debug)]
struct Pin([ u8; Self::SIZE]);

impl Pin {
  const STOP:         u8      = 0xff;
  const LENGTH:       u8      = 12;
  const CONTROL:      u8      = 0x20;
  const DIGIT_PAIRS:  usize   = Self::LENGTH as usize / 2;
  const SIZE:         usize   = 2 + Self::DIGIT_PAIRS;

  /// Get a default PIN.
  fn new(digit_pairs: &[u8; Self::DIGIT_PAIRS]) -> Self {
    let mut pin = [ ( Self::CONTROL | Self::LENGTH ), 0, 0, 0, 0, 0, 0, Self::STOP ];
    (pin[1..=Self::DIGIT_PAIRS]).copy_from_slice(digit_pairs);
    Self(pin)
  }

  fn default() -> Self {
    Self::new(&[
      // Default: 1 2 3 4 5 6 7 8 9 1 2 3
      0x12, 0x34, 0x56, 0x78, 0x91, 0x23,
    ])
  }

  /// Calculate a PIN from the pseudo-random number generator.
  fn from_prng(prng: &mut Random) -> Result<Self, Error> {
    array::try_from_fn(|_| prng.next())
    .map(|digit_pairs| Self::new(&digit_pairs))
  }
}

impl Display for Pin {
  fn fmt(&self, formatter: &mut Formatter) -> FormatResult {
    write!(formatter, "{:02x?}:", self.0)
    .and_then
    (
      |_|
      self.0.iter().skip(1).take(Self::DIGIT_PAIRS)
      .try_for_each(
        |digit_pair|
        write!(
          formatter,
          " {:x} {:x}",
          digit_pair >> 4,
          digit_pair & 0x0f,
        )
      )
    )
  }
}

/// A pseudo-random number generator to calculate the PINs.
struct Random(IntoIter<u8, {2*SHA512_HASH_LENGTH}>);

impl Random {
  /// Initialise a pseudo-random number generator.
  fn new(buffer: [u8; 2*SHA512_HASH_LENGTH]) -> Self {
    Self(buffer.into_iter())
  }

  /// Try to obtain the next valid byte.
  fn next(&mut self) -> Result<u8, Error> {
    self.0
    .find_map(
      |byte| (
        (byte < 200)
        .then_some(
          ( ((byte % 100) / 10) << 4 ) & 0xf0 // most significant digit
          | (byte % 10)                       // least significant digit
        )
      )
    )
    .ok_or("End of randomness")
  }
}

#[derive(Debug)]
struct SerialNumber([u8; Self::LENGTH]);

impl SerialNumber {
  const LENGTH: usize = 8;
}

/// Get the PIN of a single smart card.
#[allow(dead_code)]
fn try_get_pin_by_id(
  serial_numbers: MaybeSerialNumbers,
  pin_index: usize,
) -> Result<Pin, Error> {
  (pin_index < NUMBER_OF_PINS)
  .then_some(
    try_calculate_all_pins(serial_numbers)
    .map(|pin_data| pin_data[pin_index])
  )
  .transpose()?
  .ok_or("pin-index out of range")
  .inspect_err(|_| eprintln!(
      "Input parameter pin_index {} out of range (0–{})",
      pin_index,
      NUMBER_OF_PINS - 1
    )
  )
}

/// Get all PINs of all smart cards.
fn try_calculate_all_pins(serial_numbers: MaybeSerialNumbers) -> Result<ListOfPins, Error> {
  try_calculate_all_pins_with_algorithm(serial_numbers, Algorithm::DoubleSHA512)
}

/// Obtain the PINs of the  Gerätespezifische Security Module Card Konnektor.
fn try_calculate_all_pins_with_algorithm(
  serial_numbers: MaybeSerialNumbers,
  algorithm: Algorithm,
) -> Result<ListOfPins, Error> {
  match algorithm {
    Algorithm::DefaultPin => Ok([Pin::default(); NUMBER_OF_PINS]),
    Algorithm::DoubleSHA512
    =>  try_derive_prng(serial_numbers)
        .map(|mut prng| array::try_from_fn(|_| Pin::from_prng(&mut prng)))?
        .inspect_err(|error|
          eprintln!(
            "connector-ident: Could not get connector ident number: {}",
            error
          )
        ),
  }
}

/// Try to get an initialised pseudo-random number generator from either given serial numbers or by reading them from the devices.
fn try_derive_prng(serial_numbers: MaybeSerialNumbers) -> Result<Random, Error> {
  let mut buffer = [0u8; {2*SHA512_HASH_LENGTH}];

  let mut hasher = serial_numbers
  .map(|ids| Ok(ids.into()))
  .unwrap_or_else(|| try_read_serial_number_from_devices(None))
  .inspect_err(|error|
    eprintln!(
      "Could not read serial numbers from card readers: {}",
      error
    )
  )?
  .iter()
  .fold(
    Sha512::new(),
    |hasher, serial_number| hasher.chain_update(serial_number.0),
  );

  hasher.finalize_into_reset((&mut buffer[..SHA512_HASH_LENGTH]).into());
  hasher
  .chain_update(&buffer[..SHA512_HASH_LENGTH])
  .finalize_into((&mut buffer[SHA512_HASH_LENGTH..]).into());

  Ok(Random::new(buffer))
}

/// Read the serial numbers from the devices.
fn try_read_serial_number_from_devices(card_readers: Option<ListOfCardReaders>) -> Result<ListOfSerialNumbers, Error> {
  card_readers
  .unwrap_or(CARD_READERS)
  .try_map(
    |file_name| {
      let mut serial_number = [0u8; SerialNumber::LENGTH];
      File::open(file_name)
      .inspect_err(|error|
        eprintln!(
          "Cannot open file {}: {}",
          file_name,
          error
        )
      )
      .map_err(|_| "Cannot open smart card readers")?
      .read_exact(&mut serial_number)
      .map(|_| SerialNumber(serial_number))
      .inspect_err(|error|
        eprintln!(
          "Cannot read {} bytes from file {}: {}",
          serial_number.len(),
          file_name,
          error
        )
      )
      .map_err(|_| "Cannot read from file")
    }
  )
}

fn main() -> Result <(), Error> {
  try_calculate_all_pins(SERIAL_NUMBERS)?.iter().enumerate()
  .try_for_each(|(id, pin)| Ok(println!("PIN {}: {}", id, pin)))
}
