
use std::env;

fn help() {
    println!("usage:");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => {

        }
        2 => {

        }
        _ => {
            help();
        }
    }
}
