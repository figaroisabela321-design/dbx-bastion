//! Controlled admin bootstrap CLI.
//!
//! The password NEVER appears in argv (it would leak into shell history and
//! process listings). It comes from a secret file (Unix permissions are
//! refused when insecure) or from stdin.
//!
//! Usage:
//!
//! ```text
//! dbx-bastion-bootstrap --db ./bastion.db --username admin \
//!     --password-file /run/secrets/bastion_admin_pw [bootstrap]
//!
//! dbx-bastion-bootstrap --db ./bastion.db --username admin --stdin recover \
//!     --confirm RECOVER-ADMIN
//! ```
//!
//! Nothing sensitive is printed: on success only the username and user id
//! are shown.

use std::path::PathBuf;

use dbx_bastion::auth::{AdminBootstrap, BootstrapCredentials, BootstrapPolicy, PasswordService};
use dbx_bastion::BastionService;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Bootstrap,
    Recover,
}

struct Args {
    db: PathBuf,
    username: String,
    password_file: Option<PathBuf>,
    stdin_password: bool,
    command: Command,
    confirm: Option<String>,
}

fn usage() -> &'static str {
    "usage: dbx-bastion-bootstrap --db <path> --username <name> \
     (--password-file <path> | --stdin) [bootstrap|recover] [--confirm RECOVER-ADMIN]"
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1).peekable();
    let mut args = Args {
        db: PathBuf::from("./bastion.db"),
        username: String::new(),
        password_file: None,
        stdin_password: false,
        command: Command::Bootstrap,
        confirm: None,
    };
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--db" => {
                args.db = PathBuf::from(iter.next().ok_or("missing value for --db")?);
            }
            "--username" => {
                args.username = iter.next().ok_or("missing value for --username")?;
            }
            "--password-file" => {
                args.password_file = Some(PathBuf::from(iter.next().ok_or("missing value for --password-file")?));
            }
            "--stdin" => args.stdin_password = true,
            "--confirm" => {
                args.confirm = Some(iter.next().ok_or("missing value for --confirm")?);
            }
            "bootstrap" => args.command = Command::Bootstrap,
            "recover" => args.command = Command::Recover,
            "--help" | "-h" => return Err(usage().to_string()),
            other => return Err(format!("unexpected argument: {other}\n{usage}", usage = usage())),
        }
    }
    if args.username.trim().is_empty() {
        return Err(format!("--username is required\n{}", usage()));
    }
    if args.password_file.is_none() && !args.stdin_password {
        return Err(format!(
            "--password-file or --stdin is required (passwords are never passed via argv)\n{}",
            usage()
        ));
    }
    Ok(args)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = parse_args()?;

    // Credential channel: secret file or stdin. Never argv, never logged.
    let creds = if let Some(path) = &args.password_file {
        BootstrapCredentials::from_secret_file(&args.username, path)
    } else {
        BootstrapCredentials::from_stdin(&args.username)
    }
    .map_err(|error| error.to_string())?;

    let service = BastionService::open(&args.db).map_err(|error| error.to_string())?;
    let bootstrap = AdminBootstrap::new(
        service.store().clone(),
        PasswordService::new(Default::default()).map_err(|error| error.to_string())?,
        BootstrapPolicy::default(),
    );

    match args.command {
        Command::Bootstrap => {
            let id = bootstrap.bootstrap(&creds).await.map_err(|error| error.to_string())?;
            println!("admin '{}' initialized (id {id})", creds.username);
        }
        Command::Recover => {
            let confirm = args.confirm.as_deref().unwrap_or("");
            let id = bootstrap.recover_admin(&creds, confirm).await.map_err(|error| error.to_string())?;
            println!("admin '{}' recovered (id {id})", creds.username);
        }
    }
    Ok(())
}
