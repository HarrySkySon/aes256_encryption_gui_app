/*
The code is a simple file encryption/decryption application using the Iced GUI library.
It allows the user to browse for a file, input a password, choose between encryption
and decryption, and process the file accordingly. The encryption/decryption is done
using the AES-256 algorithm in CBC mode with PKCS7 padding.
 */
use aes::{Aes256, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use generic_array::GenericArray;
use iced::{button, text_input, Application, Button, Column, Command, Container, Element, Length, Radio, Row, Settings, Text, TextInput};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str;
use std::fmt;

#[derive(Default)]
struct App {
    file_path: Option<PathBuf>,
    password: String,
    mode: Mode,
    browse_button: button::State,
    password_input: text_input::State,
    process_button: button::State,
    message: String, // Added this field to store the message text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Encrypt
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Encrypt => write!(f, "Encrypt"),
            Mode::Decrypt => write!(f, "Decrypt"),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    BrowseFile,
    FileSelected(PathBuf),
    PasswordChanged(String),
    ModeChanged(Mode),
    ProcessFile,
}

impl Application for App {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (Self::default(), Command::none())
    }

    fn title(&self) -> String {
        String::from("File Encryptor/Decryptor")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::BrowseFile => {
                let file_dialog = rfd::FileDialog::new().pick_file();
                if let Some(file) = file_dialog {
                    self.file_path = Some(file.clone());
                    return Command::perform(async move { Message::FileSelected(file) }, |msg| msg);
                }
            }
            Message::FileSelected(file) => {
                self.file_path = Some(file);
            }
            Message::PasswordChanged(password) => {
                self.password = password;
            }
            Message::ModeChanged(mode) => {
                self.mode = mode;
            }
            Message::ProcessFile => {
                if let Some(file_path) = &self.file_path {
                    let key = password_to_key(&self.password);

                    let iv = [0u8; 16];
                    let key = GenericArray::from_slice(&key);
                    let cipher = Aes256::new(&key);
                    let iv = GenericArray::from_slice(&iv);
                    let block_mode = Cbc::<Aes256, Pkcs7>::new(cipher, iv);

                    let mut file = File::open(file_path).expect("Failed to open file");
                    let mut file_content = Vec::new();
                    file.read_to_end(&mut file_content).expect("Failed to read file");

                    let result = match self.mode {
                        Mode::Encrypt => {
                            let encrypted = block_mode.encrypt_vec(&file_content);
                            encrypted
                        }
                        Mode::Decrypt => {
                            let decrypted = block_mode.decrypt_vec(&file_content).unwrap();
                            decrypted
                        }
                    };

                    let output_file_path = format!("{}_{}", file_path.display(), self.mode);
                    let mut output_file = File::create(&output_file_path).expect("Failed to create output file");
                    output_file.write_all(&result).expect("Failed to write output file");

                    // Updated this line to set the message text instead of printing it to the console
                    self.message = format!("{}ed file saved as: {}", self.mode, output_file_path);
                }
            }
        }

        Command::none()
    }

    fn view(&mut self) -> Element<Message> {
        let file_path = self.file_path.as_ref().map_or("No file selected", |p| p.to_str().unwrap());

        let browse_button = Button::new(&mut self.browse_button, Text::new("Browse file"))
            .on_press(Message::BrowseFile);

        let password_input = TextInput::new(&mut self.password_input, "Enter password", &self.password, Message::PasswordChanged)
            .password();

        let mode_radio = Row::new()
            .push(Radio::new(Mode::Encrypt, "Encrypt", Some(self.mode), Message::ModeChanged))
            .push(Radio::new(Mode::Decrypt, "Decrypt", Some(self.mode), Message::ModeChanged));

        let process_button = Button::new(&mut self.process_button, Text::new("Process file"))
            .on_press(Message::ProcessFile);

        let message_text = Text::new(&self.message); // Added this line to display the message text

        let content = Column::new()
            .padding(20)
            .spacing(20)
            .push(Text::new(file_path))
            .push(browse_button)
            .push(password_input)
            .push(mode_radio)
            .push(process_button)
            .push(message_text); // Added this line to

        // Convert dimensions from millimeters to pixels (assuming 96 DPI)
        let width_px: f32 = (100.0 / 25.4) * 96.0;
        let height_px: f32 = (100.0 / 25.4) * 96.0;

        Container::new(content)
            .width(Length::Units(width_px.round() as u16))
            .height(Length::Units(height_px.round() as u16))
            .center_x()
            .center_y()
            .into()
    }
}

fn password_to_key(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let password_bytes = password.as_bytes();
    for (i, byte) in password_bytes.iter().enumerate() {
        key[i % 32] ^= *byte;
    }
    key
}

fn main() {
    // Use unwrap() to handle the Result returned by App::run(Settings::default())
    App::run(Settings::default()).unwrap();
}