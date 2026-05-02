#![cfg(feature = "integration")]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use uuid::Uuid;

#[derive(Clone, Copy)]
struct DriverRequirement {
    kind: &'static str,
    name: &'static str,
}

struct BlueprintCase {
    path: &'static str,
    env_vars: &'static [&'static str],
    drivers: &'static [DriverRequirement],
}

const AGENT_HERMES: DriverRequirement = DriverRequirement {
    kind: "agent",
    name: "hermes",
};
const CONTEXT_NEXUS: DriverRequirement = DriverRequirement {
    kind: "context",
    name: "nexus",
};

const CASES: &[BlueprintCase] = &[
    BlueprintCase {
        path: "blueprints/claude+filesystem+openshell.yaml",
        env_vars: &["ANTHROPIC_API_KEY"],
        drivers: &[],
    },
    BlueprintCase {
        path: "blueprints/codex+filesystem+openshell.yaml",
        env_vars: &["OPENAI_API_KEY"],
        drivers: &[],
    },
    BlueprintCase {
        path: "blueprints/openclaw+filesystem+openshell.yaml",
        env_vars: &["OPENAI_API_KEY"],
        drivers: &[],
    },
    BlueprintCase {
        path: "blueprints/claude+mcp-generic+openshell.yaml",
        env_vars: &["ANTHROPIC_API_KEY", "MCP_URL", "MCP_TOKEN"],
        drivers: &[],
    },
    BlueprintCase {
        path: "blueprints/hermes+filesystem+openshell.yaml",
        env_vars: &["OPENAI_API_KEY"],
        drivers: &[AGENT_HERMES],
    },
    BlueprintCase {
        path: "blueprints/claude+nexus+openshell.yaml",
        env_vars: &["ANTHROPIC_API_KEY", "NEXUS_HUB_URL", "NEXUS_TOKEN"],
        drivers: &[CONTEXT_NEXUS],
    },
    BlueprintCase {
        path: "blueprints/codex+mcp-generic+openshell.yaml",
        env_vars: &["OPENAI_API_KEY", "MCP_URL", "MCP_TOKEN"],
        drivers: &[],
    },
    BlueprintCase {
        path: "blueprints/hermes+nexus+openshell.yaml",
        env_vars: &["OPENAI_API_KEY", "NEXUS_HUB_URL", "NEXUS_TOKEN"],
        drivers: &[AGENT_HERMES, CONTEXT_NEXUS],
    },
    BlueprintCase {
        path: "blueprints/openclaw+nexus+openshell.yaml",
        env_vars: &["OPENAI_API_KEY", "NEXUS_HUB_URL", "NEXUS_TOKEN"],
        drivers: &[CONTEXT_NEXUS],
    },
];

#[test]
#[ignore = "requires OpenShell and blueprint-specific credentials or subprocess drivers"]
fn reference_blueprints_create_exec_destroy() -> Result<(), Box<dyn std::error::Error>> {
    if !command_status_ok("openshell", ["--version"])? {
        println!(
            "skipping blueprint integration tests: `openshell --version` failed or is missing"
        );
        return Ok(());
    }

    let workspace = workspace_root();
    let driver_output = agentenv_output(&workspace, ["drivers", "list"])?;
    if !driver_output.status.success() {
        println!(
            "skipping blueprint integration tests: `agentenv drivers list` failed\n{}",
            String::from_utf8_lossy(&driver_output.stderr)
        );
        return Ok(());
    }
    let drivers = String::from_utf8_lossy(&driver_output.stdout);

    for case in CASES {
        run_case_if_eligible(&workspace, case, &drivers)?;
    }

    Ok(())
}

fn run_case_if_eligible(
    workspace: &PathBuf,
    case: &BlueprintCase,
    drivers: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let missing_env: Vec<&str> = case
        .env_vars
        .iter()
        .copied()
        .filter(|name| env::var(name).map_or(true, |value| value.trim().is_empty()))
        .collect();
    if !missing_env.is_empty() {
        println!(
            "skipping {}: missing required env var(s): {}",
            case.path,
            missing_env.join(", ")
        );
        return Ok(());
    }

    for driver in case.drivers {
        if !driver_list_contains(drivers, driver) {
            println!(
                "skipping {}: missing required driver: {} {}",
                case.path, driver.kind, driver.name
            );
            return Ok(());
        }
    }

    run_case(workspace, case)
}

fn run_case(workspace: &PathBuf, case: &BlueprintCase) -> Result<(), Box<dyn std::error::Error>> {
    let id = Uuid::new_v4().simple().to_string();
    let env_name = format!("{}-{id}", env_name_stem(case.path));
    let home = env::temp_dir().join(format!("agentenv-blueprint-{id}"));
    let projects = home.join("projects");
    fs::create_dir_all(&projects)?;
    fs::write(projects.join("README.md"), "# Blueprint integration\n")?;

    let blueprint = workspace.join(case.path);
    let create = agentenv_output_with_home(
        workspace,
        &home,
        [
            OsString::from("create"),
            OsString::from(&env_name),
            OsString::from("--blueprint"),
            blueprint.into_os_string(),
            OsString::from("--non-interactive"),
        ],
    )?;
    if !create.status.success() {
        panic!(
            "`agentenv create` failed for {}\nenv: {}\ntemp HOME preserved at: {}\nstdout:\n{}\nstderr:\n{}",
            case.path,
            env_name,
            home.display(),
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr)
        );
    }

    let exec = agentenv_output_with_home(
        workspace,
        &home,
        [
            OsString::from("exec"),
            OsString::from(&env_name),
            OsString::from("--"),
            OsString::from("echo"),
            OsString::from("ok"),
        ],
    );
    let destroy = agentenv_output_with_home(
        workspace,
        &home,
        [
            OsString::from("destroy"),
            OsString::from(&env_name),
            OsString::from("--yes"),
            OsString::from("--non-interactive"),
        ],
    );

    let destroy = match destroy {
        Ok(output) => output,
        Err(error) => {
            panic!(
                "failed to run `agentenv destroy` for {}\nenv: {}\ntemp HOME preserved at: {}\nerror: {}",
                case.path,
                env_name,
                home.display(),
                error
            );
        }
    };
    if !destroy.status.success() {
        panic!(
            "`agentenv destroy` failed for {}\nenv: {}\ntemp HOME preserved at: {}\nstdout:\n{}\nstderr:\n{}",
            case.path,
            env_name,
            home.display(),
            String::from_utf8_lossy(&destroy.stdout),
            String::from_utf8_lossy(&destroy.stderr)
        );
    }
    remove_temp_home(&home);

    let exec = exec?;
    assert!(
        exec.status.success(),
        "`agentenv exec` failed for {}\nstdout:\n{}\nstderr:\n{}",
        case.path,
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr)
    );
    assert!(
        String::from_utf8_lossy(&exec.stdout).contains("ok"),
        "`agentenv exec` stdout for {} did not contain `ok`\nstdout:\n{}\nstderr:\n{}",
        case.path,
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr)
    );

    Ok(())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("blueprint-integration is under tests/")
        .to_path_buf()
}

fn driver_list_contains(output: &str, required: &DriverRequirement) -> bool {
    output.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let kind = fields.next();
        let name = fields.next();
        let _version = fields.next();
        let source = fields.next();

        kind == Some(required.kind)
            && name == Some(required.name)
            && matches!(source, Some("installed" | "override"))
    })
}

fn agentenv_output<const N: usize>(
    workspace: &PathBuf,
    args: [&str; N],
) -> Result<Output, Box<dyn std::error::Error>> {
    let args = args.map(OsString::from);
    agentenv_output_with_home(workspace, &workspace.join(".target-test-home"), args)
}

fn agentenv_output_with_home<const N: usize>(
    workspace: &PathBuf,
    home: &PathBuf,
    args: [OsString; N],
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = agentenv_command(workspace);
    command
        .args(args)
        .env("HOME", home)
        .env("AGENTENV_DISABLE_KEYRING", "1")
        .current_dir(workspace);
    if let Some(driver_path) = driver_path_with_original_home() {
        command.env("AGENTENV_DRIVER_PATH", driver_path);
    }
    Ok(command.output()?)
}

fn agentenv_command(workspace: &PathBuf) -> Command {
    if let Ok(binary) = env::var("AGENTENV_BIN") {
        Command::new(binary)
    } else {
        let mut command = Command::new("cargo");
        command.args(["run", "--quiet", "-p", "agentenv", "--"]);
        command.current_dir(workspace);
        command
    }
}

fn command_status_ok<const N: usize>(
    program: &str,
    args: [&str; N],
) -> Result<bool, Box<dyn std::error::Error>> {
    match Command::new(program).args(args).status() {
        Ok(status) => Ok(status.success()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Box::new(error)),
    }
}

fn env_name_stem(path: &str) -> String {
    path.rsplit('/')
        .next()
        .unwrap_or(path)
        .trim_end_matches(".yaml")
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn driver_path_with_original_home() -> Option<OsString> {
    let original_home_drivers = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".agentenv/drivers"));
    let paths: Vec<PathBuf> = env::var_os("AGENTENV_DRIVER_PATH")
        .map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(original_home_drivers)
        .collect();

    if paths.is_empty() {
        None
    } else {
        env::join_paths(paths).ok()
    }
}

fn remove_temp_home(home: &PathBuf) {
    if let Err(error) = fs::remove_dir_all(home) {
        eprintln!("failed to remove temp HOME `{}`: {error}", home.display());
    }
}

#[test]
fn driver_list_contains_requires_subprocess_source() {
    let output = "\
KIND       NAME                     VERSION        SOURCE     BINARY
agent      hermes                   0.0.1-alpha0   built-in   -
context    nexus                    0.0.1-alpha0   built-in   -
agent      hermes                   0.0.1-alpha0   installed  /tmp/hermes
context    nexus                    0.0.1-alpha0   override   /tmp/nexus
";

    assert!(driver_list_contains(output, &AGENT_HERMES));
    assert!(driver_list_contains(output, &CONTEXT_NEXUS));

    let built_in_only = "\
KIND       NAME                     VERSION        SOURCE     BINARY
agent      hermes                   0.0.1-alpha0   built-in   -
context    nexus                    0.0.1-alpha0   built-in   -
";

    assert!(!driver_list_contains(built_in_only, &AGENT_HERMES));
    assert!(!driver_list_contains(built_in_only, &CONTEXT_NEXUS));
}
