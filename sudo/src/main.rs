mod cli_args;
use clap::Parser;
use cli_args::Cli;
#[derive(Debug)]
struct CustomError(String);

// fn main() {
fn main() -> Result<(), CustomError> {

    let args = Cli::parse();
    // let content = std::fs::read_to_string(&args.path);
    // if let Some(content) = args.path.as_deref() {
    if let Some(cli_path) = args.path.as_deref() {
        let content = cli_path.display();
        println!("path: {}", content);
        println!("Value for content: {:?}", std::fs::read_to_string(content.to_string()));
    }

    println!("args: {:?}", args);
    Ok(())
}

// try to exclude flags
// write tests
// catch trailing stuff (the commands for which are meant to be executed with root rights)


// unsolved: how can we pass yet unknown env variables?