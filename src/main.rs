use std::{
  fs::File,
  io::Read,
};
use sha2::{Sha512, Digest};

#[allow(dead_code)]
fn get_smart_card_pins_by_id(
  ids: Option<[ [ u8; 8 ]; 3 ]>,
  pin_index: usize
) -> Result<[ u8; 8 ], &'static str> {
  match pin_index {
    0 ..= 5 => get_smart_card_pins(ids).map(|pin_data| pin_data[pin_index]),
    _ => {
      eprintln!("connector-ident: Input parameter pinIndex out of range");
      Err("pin-index out of range (0–5)")
    },
  }
}

fn get_smart_card_pins(
  ids: Option<[ [ u8; 8 ]; 3 ]>
) -> Result<[ [ u8; 8 ]; 6 ], &'static str> {
  get_smart_card_pins_by_algorithm(ids, 3)
}

const PIN_STOP: u8 = 0xff;
const PIN_LENGTH: u8 = 12;
const PIN_CONTROL: u8 = 0x20;

fn get_smart_card_pins_by_algorithm(
  ids: Option<[ [ u8; 8 ]; 3 ]>,
  algorithm: usize
) -> Result<[ [ u8; 8 ]; 6 ], &'static str> {
  if algorithm == 0 {
    Ok(
      (0 ..= 5)
      .map(|_| [
        ( PIN_CONTROL | PIN_LENGTH ),
        // Default: 1 2 3 4 5 6 7 8 9 1 2 3
        0x12, 0x34, 0x56, 0x78, 0x91, 0x23,
        PIN_STOP
      ])
      .collect::<Vec<[ u8; 8 ]>>()
      .try_into()
      .unwrap()
    )
  } else {
    connector_ident_number(ids, algorithm)
    .map(|buffer| {
      let mut pin_data = [ [ 0u8; 8 ]; 6 ];
      let mut offset = 0;

      for pin in 0 ..= 5 {
        pin_data[pin][0] = PIN_CONTROL | PIN_LENGTH;
        pin_data[pin][7] = PIN_STOP;

        let mut digit_pair = 1;
        loop {
          if offset < buffer.len() {
            let byte = buffer[offset];
            offset += 1;
            if byte < 200 {
              pin_data[pin][digit_pair]
              = ( ((byte % 100) / 10) << 4 ) & 0xf0 // most significant digit
              | (byte % 10);                        // least significant digit
              digit_pair += 1;
              if digit_pair >= 7 {
                break Ok(())
              }
            }
          } else {
            break Err("End of randomness");
          }
        }?;
      }
      Ok(pin_data)
    })?
    .map_err(|error| {
      eprintln!("connector-ident: Could not get connector ident number!!!");
      error
    })
  }
}

fn connector_ident_number(
  ids: Option<[ [ u8; 8 ]; 3 ]>,
  algorithm: usize
) -> Result<[ u8; 0x80 ], &'static str> {
  if algorithm == 3 {
    ids
    .map(|ids| Ok(ids))
    .unwrap_or_else(read_smart_card_reader_info)
    .map(|reader_info| {
      let mut buffer = [ 0u8; 0x80 ];

      let mut array = Sha512::new()
      .chain_update(reader_info[0])
      .chain_update(reader_info[1])
      .chain_update(reader_info[2])
      .finalize();

      buffer[..0x40].clone_from_slice(&array[..]);

      Sha512::new()
      .chain_update(&array)
      .finalize_into(&mut array);
      buffer[0x40..].clone_from_slice(&array[..]);

      buffer
    })
    .map_err(|error| {
      eprintln!("connector-ident: Could not read SC reader infos");
      error
    })
  } else {
    eprintln!("connector-ident: ident_algo not / no longer supported");
    Err("Invalid algorithm")
  }
}

fn read_smart_card_reader_info() -> Result<[ [ u8; 8 ]; 3 ], &'static str> {
  let mut output = [ [ 0u8; 8 ]; 3 ];
  for (index, file_name) in [
    "/sys/bus/usb/devices/1-4/serial",
    "/sys/bus/usb/devices/1-5/serial",
    "/sys/bus/usb/devices/1-6/serial",
  ].iter().enumerate() {
    match File::open(file_name) {
      Ok(mut file) => {
        match file.read(&mut output[index]) {
          Ok(count) => if count != output.len() {
            eprintln!("Error: Read {} Bytes serial number instead of {}", count, output.len());
            eprintln!("Error: Read {:?}", output[0]);
            return Err("Invalid number of bytes");
          },
          Err(error) => {
            eprintln!("Error: Cannot Read: {}", error);
            return Err("Cannot read from file");
          }
        }
      },
      Err(error) => {
        eprintln!("readSCReaderInfo: error opening file {}: {}", file_name, error);
        return Err("Cannot open smart card reader");
      },
    }
  }
  Ok(output)
}

fn main() -> Result <(), &'static str> {
  let ids = Some([
    *b"13372342",
    *b"meowmeow",
    *b"*squeak*",
  ]);
  for (id, pin) in get_smart_card_pins(ids)?.iter().enumerate() {
    println!("PIN {}: {:02x?}", id, pin);
  }
  Ok(())
}
