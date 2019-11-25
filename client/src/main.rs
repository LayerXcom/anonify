#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

use std::path::PathBuf;
use clap::{Arg, App, SubCommand, AppSettings, ArgMatches};
use rand::{rngs::OsRng, Rng};
use term::Term;
use crate::config::*;
use crate::commands::*;

mod term;
mod config;
mod commands;
mod error;

fn main() {
    let default_root_dir = get_default_root_dir();

    let matches = App::new("zface")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .version(crate_version!())
        .author(crate_authors!())
        .about("Anonify's command line interface")
        .subcommand(anonify_commands_definition())
        .get_matches();

    let mut term = term::Term::new(config_terminal(&matches));
    let root_dir = global_rootdir_match(&default_root_dir, &matches);
    let rng = &mut OsRng;

    match matches.subcommand() {
        (ANONIFY_COMMAND, Some(matches)) => subcommand_anonify(term, root_dir, matches, rng),
        _ => {
            term.error(matches.usage()).unwrap();
            std::process::exit(1);
        }
    }
}

//
// Anonify Sub Commands
//

const ANONIFY_COMMAND: &'static str = "anonify";

fn subcommand_anonify<R: Rng>(mut term: Term, root_dir: PathBuf, matches: &ArgMatches, rng: &mut R) {
    match matches.subcommand() {
        ("get-state", Some(matches)) => {
            get_state(&mut term, root_dir);
        },
        _ => {
            term.error(matches.usage()).unwrap();
            std::process::exit(1);
        }
    };
}

fn anonify_commands_definition<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name(ANONIFY_COMMAND)
        .about("Anonify operations")
        .subcommand(SubCommand::with_name("get-state"))
            .about("Get state from anonify services.")
}


// .arg(Arg::with_name("target address")
//                 .short("to")
//                 .long("target-address")
//                 .help("Specify a target address.")
//                 .takes_value(true)
//                 .required(true)
//             )
