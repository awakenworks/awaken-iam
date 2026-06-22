//! Project automation and mechanical guardrail enforcement.

use std::env;
use std::process::{Command, ExitCode};

#[derive(Debug, Clone)]
struct Package {
    name: String,
    deps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Violation {
    guardrail: &'static str,
    message: String,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("guardrail-lints") => {
            run_guardrail_lints(args.iter().any(|a| a == "--self-check"))
        }
        Some("help" | "--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("xtask: unknown command `{other}`\n");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "xtask — Awaken IAM automation\n\n\
         USAGE:\n    \
         cargo run -p xtask -- <command>\n\n\
         COMMANDS:\n    \
         guardrail-lints              run every guardrail over the workspace\n    \
         guardrail-lints --self-check verify the enforcers against synthetic input\n    \
         help                         print this message"
    );
}

fn run_guardrail_lints(self_check: bool) -> ExitCode {
    if self_check {
        return match self_check_enforcers() {
            Ok(()) => {
                println!("guardrail self-check: ok");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("guardrail self-check FAILED: {message}");
                ExitCode::FAILURE
            }
        };
    }

    let packages = match load_workspace_packages() {
        Ok(packages) => packages,
        Err(message) => {
            eprintln!("xtask: could not read workspace metadata: {message}");
            return ExitCode::FAILURE;
        }
    };

    let mut violations = Vec::new();
    violations.extend(check_contract_boundary(&packages));
    violations.extend(check_core_server_boundary(&packages));
    violations.extend(check_client_server_boundary(&packages));
    violations.extend(check_no_product_runtime_deps(&packages));

    if violations.is_empty() {
        println!("guardrail-lints: ok ({} packages checked)", packages.len());
        ExitCode::SUCCESS
    } else {
        for v in &violations {
            eprintln!("[{}] {}", v.guardrail, v.message);
        }
        eprintln!("\nguardrail-lints: {} violation(s)", violations.len());
        ExitCode::FAILURE
    }
}

fn check_contract_boundary(packages: &[Package]) -> Vec<Violation> {
    find_forbidden_deps(
        packages,
        "G1",
        "awaken-iam-contract",
        &["awaken-iam-core", "awaken-iam-client", "awaken-iam-server"],
    )
}

fn check_core_server_boundary(packages: &[Package]) -> Vec<Violation> {
    find_forbidden_deps(packages, "G2", "awaken-iam-core", &["awaken-iam-server"])
}

fn check_client_server_boundary(packages: &[Package]) -> Vec<Violation> {
    find_forbidden_deps(packages, "G3", "awaken-iam-client", &["awaken-iam-server"])
}

fn check_no_product_runtime_deps(packages: &[Package]) -> Vec<Violation> {
    let forbidden_prefixes = ["oversight-", "awaken-next-", "oversight-pack-hub-"];
    packages
        .iter()
        .filter(|pkg| pkg.name.starts_with("awaken-iam"))
        .flat_map(|pkg| {
            pkg.deps
                .iter()
                .filter(|dep| {
                    forbidden_prefixes
                        .iter()
                        .any(|prefix| dep.starts_with(prefix))
                })
                .map(move |dep| Violation {
                    guardrail: "G4",
                    message: format!(
                        "IAM crate `{}` must not depend on product runtime crate `{}`",
                        pkg.name, dep
                    ),
                })
        })
        .collect()
}

fn find_forbidden_deps(
    packages: &[Package],
    guardrail: &'static str,
    subject: &str,
    forbidden: &[&str],
) -> Vec<Violation> {
    packages
        .iter()
        .filter(|pkg| pkg.name == subject)
        .flat_map(|pkg| {
            pkg.deps
                .iter()
                .filter(|dep| forbidden.contains(&dep.as_str()))
                .map(move |dep| Violation {
                    guardrail,
                    message: format!("crate `{}` must not depend on `{}`", pkg.name, dep),
                })
        })
        .collect()
}

fn load_workspace_packages() -> Result<Vec<Package>, String> {
    let output = Command::new(env::var("CARGO").as_deref().unwrap_or("cargo"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .map_err(|e| format!("failed to spawn cargo: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    parse_packages(&json)
}

fn parse_packages(json: &serde_json::Value) -> Result<Vec<Package>, String> {
    let packages = json
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or("metadata has no `packages` array")?;
    Ok(packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?.to_owned();
            let deps = pkg
                .get("dependencies")?
                .as_array()?
                .iter()
                .filter_map(|d| Some(d.get("name")?.as_str()?.to_owned()))
                .collect();
            Some(Package { name, deps })
        })
        .collect())
}

fn self_check_enforcers() -> Result<(), String> {
    let clean = vec![
        Package {
            name: "awaken-iam-contract".into(),
            deps: vec!["serde".into()],
        },
        Package {
            name: "awaken-iam-core".into(),
            deps: vec!["awaken-iam-contract".into()],
        },
        Package {
            name: "awaken-iam-client".into(),
            deps: vec!["awaken-iam-contract".into()],
        },
    ];
    if !check_contract_boundary(&clean).is_empty()
        || !check_core_server_boundary(&clean).is_empty()
        || !check_client_server_boundary(&clean).is_empty()
        || !check_no_product_runtime_deps(&clean).is_empty()
    {
        return Err("guardrails flagged a clean workspace".into());
    }

    let dirty_contract = vec![Package {
        name: "awaken-iam-contract".into(),
        deps: vec!["awaken-iam-server".into()],
    }];
    if check_contract_boundary(&dirty_contract).len() != 1 {
        return Err("G1 did not catch contract -> server dependency".into());
    }

    let dirty_core = vec![Package {
        name: "awaken-iam-core".into(),
        deps: vec!["awaken-iam-server".into()],
    }];
    if check_core_server_boundary(&dirty_core).len() != 1 {
        return Err("G2 did not catch core -> server dependency".into());
    }

    let dirty_client = vec![Package {
        name: "awaken-iam-client".into(),
        deps: vec!["awaken-iam-server".into()],
    }];
    if check_client_server_boundary(&dirty_client).len() != 1 {
        return Err("G3 did not catch client -> server dependency".into());
    }

    let dirty_runtime = vec![Package {
        name: "awaken-iam-core".into(),
        deps: vec!["oversight-server".into()],
    }];
    if check_no_product_runtime_deps(&dirty_runtime).len() != 1 {
        return Err("G4 did not catch IAM -> product runtime dependency".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcer_self_check_passes() {
        self_check_enforcers().unwrap();
    }

    #[test]
    fn parse_packages_reads_names_and_deps() {
        let json = serde_json::json!({
            "packages": [
                { "name": "a", "dependencies": [ { "name": "b" } ] }
            ]
        });
        let pkgs = parse_packages(&json).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "a");
        assert_eq!(pkgs[0].deps, vec!["b".to_string()]);
    }
}
