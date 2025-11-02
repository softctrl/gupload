// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Ponto de entrada da aplicação CLI GuardUpload.

use guardupload::cli::GuardUploadCli;

fn main() {
    match GuardUploadCli::run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err:?}");
            std::process::exit(2);
        }
    }
}
