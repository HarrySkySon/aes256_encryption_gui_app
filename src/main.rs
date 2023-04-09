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
//a struct App contains different elements such as file_path, password,
// mode, browse_button, password_input, process_button and message. The App's
// update and view methods are overridden to update the App with a Message
// enum or produce an Element. The password_to_key function is used to generate
// an AES-256 key from the provided password. The main function runs the application.
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
//Mode is an enumeration type which defines a set of named constants. In this case,
// the two constants are "Encrypt" and "Decrypt", representing the two possible modes
// of operation. This type of data structure allows for cleaner, more reliable code by
// making the intention of the code clearer and less prone to errors.
enum Mode {
    Encrypt,
    Decrypt,
}

//The above code is creating a default implementation of the Mode enum. The default
// implementation is set to Mode::Encrypt, meaning that if no other Mode is specified,
// the code will use the encryption mode.
impl Default for Mode {
    fn default() -> Self {
        Mode::Encrypt
    }
}

//The function fmt is overriding the implementation of std::fmt::Display for the Mode enum.
// The implementation uses a match statement to check for the variant of the enum, and then
// use the write! macro to print the string representation.
// The write! macro returns a fmt::Result which is used as the return value of the fmt function.
impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Encrypt => write!(f, "Encrypt"),
            Mode::Decrypt => write!(f, "Decrypt"),
        }
    }
}

#[derive(Debug, Clone)]
//The Message enum is being used to define a set of types that could be used for
// communication between different parts of an application. The different variants of
// the Message enum define specific types of messages that can be sent and received.
// For example, the BrowseFile variant would be sent to request the user to browse for
// a file, and the FileSelected variant would be sent in response with the path of the
// selected file. Similarly, the PasswordChanged variant would be sent to indicate the
// user has changed their password, and the ModeChanged variant would be sent to indicate
// the user has changed their mode. Finally, the ProcessFile variant would be sent to
// indicate that the application should process the provided file.
enum Message {
    BrowseFile,
    FileSelected(PathBuf),
    PasswordChanged(String),
    ModeChanged(Mode),
    ProcessFile,
}

//The Application trait is a trait from the iced library that is used to define
// a type-level interface for creating a GUI application. The App type is then
// implementing this trait, which requires providing three type parameters: Executor,
// Message, and Flags. The Executor type is used to define what executor will be used
// to run the application, the Message type is used to define what type of messages
// will be sent between the application and its components, and the Flags type is used
// to define any custom flags that may be used with the application.
impl Application for App {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Flags = ();

    //The function creates an instance of Self (in this case, Self is a type of command)
    // and a Command<Message> object. The _flags parameter is unused and so is ignored by
    // the function. The function then returns a tuple containing the newly created Self
    // object and Command<Message> object.
    fn new(_flags: ()) -> (Self, Command<Message>) {
        (Self::default(), Command::none())
    }

    //The title() method is a method on the self parameter. This method returns a String
    // that contains the title of the program: "File Encryptor/Decryptor". This title is
    // used throughout the application and is displayed in the user interface.
    fn title(&self) -> String {
        String::from("File Encryptor/Decryptor")
    }

    //The function is matching against a given message and depending on what message is provided,
    // it will do different things. In this case, it is checking if the message is a
    // Message::BrowseFile and if it is, it will open up a file dialog and set the
    // file_path to the selected file. It then returns a Command that will perform
    // the Message::FileSelected action, with the selected file as the parameter.
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

//This function takes a string (password) as the parameter and returns an array of 32
// 8-bit unsigned integers (key). The function first initializes an array of 32 8-bit
// unsigned integers filled with 0s to be used as the key. It then takes the password
// string and converts it to an array of bytes (password_bytes). The function then
// iterates through the elements of password_bytes and XORs each element with the
// corresponding element in the key array (i % 32). This process creates a new key
// that is a combination of the original password and the zero-filled array. The new
// key is then finally returned.
fn password_to_key(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let password_bytes = password.as_bytes();
    for (i, byte) in password_bytes.iter().enumerate() {
        key[i % 32] ^= *byte;
    }
    key
}
 //The main() function is the entry point for the program. It calls the App::run() function
 // with the default settings from the Settings module. The App::run() function is responsible
 // for setting up the program's environment, launching the application, and handling any
 // errors. If everything goes according to plan, the program will run successfully and the
 // App::run() function will return an Ok(), which the main() function then handles.
fn main() {
    // Use unwrap() to handle the Result returned by App::run(Settings::default())
    App::run(Settings::default()).unwrap();
}