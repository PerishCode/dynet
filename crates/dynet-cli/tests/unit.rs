#[path = "../src/cli/mod.rs"]
mod cli;
#[path = "../src/config.rs"]
mod config;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/output.rs"]
mod output;
#[path = "../src/platform.rs"]
mod platform;

#[path = "unit/boundary.rs"]
mod boundary_cases;
#[path = "unit/cli.rs"]
mod cli_cases;
#[path = "unit/config.rs"]
mod config_cases;
#[path = "unit/output.rs"]
mod output_cases;
#[path = "unit/plan.rs"]
mod plan_cases;
