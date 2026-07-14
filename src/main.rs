mod scanner;
mod generator;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

/// dora2tf — Generates Terraform HCL from live AWS resources
#[derive(Parser, Debug)]
#[command(name = "dora2tf", version, about = "Generate Terraform .tf files from AWS resources")]
struct Cli {
    /// AWS profile name
    #[arg(short, long, default_value = "default")]
    profile: String,

    /// AWS region
    #[arg(short, long)]
    region: String,

    /// Output directory for .tf files
    #[arg(short, long, default_value = "./terraform")]
    output: PathBuf,

    /// Resource types to scan: ec2, sg, vpc, iam, all
    #[arg(short, long, default_value = "all")]
    types: String,

    /// Dry run: show what would be generated without writing files
    #[arg(long)]
    dry_run: bool,

    /// Generate import.sh script alongside .tf files
    #[arg(long)]
    import_script: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    info!("dora2tf v{} — region={} profile={}", env!("CARGO_PKG_VERSION"), cli.region, cli.profile);

    // AWS SDK config
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .profile_name(&cli.profile)
        .region(aws_config::Region::new(cli.region.clone()))
        .load()
        .await;
    let ec2_client = aws_sdk_ec2::Client::new(&config);
    let iam_client = aws_sdk_iam::Client::new(&config);

    let types: Vec<&str> = if cli.types == "all" {
        vec!["ec2", "sg", "vpc", "iam"]
    } else {
        cli.types.split(',').map(|s| s.trim()).collect()
    };

    let mut resources = generator::Resources::default();

    // ── Scan ────────────────────────────────────────────────────────────
    for t in &types {
        info!("Scanning: {}", t);
        match *t {
            "ec2" => resources.instances = scanner::ec2::scan_instances(&ec2_client).await?,
            "sg"  => resources.security_groups = scanner::sg::scan_security_groups(&ec2_client).await?,
            "vpc" => resources.vpcs = scanner::vpc::scan_vpcs(&ec2_client).await?,
            "iam" => resources.roles = scanner::iam::scan_roles(&iam_client).await?,
            _ => anyhow::bail!("Unknown type: {}. Valid: ec2, sg, vpc, iam, all", t),
        }
    }

    // ── Generate ────────────────────────────────────────────────────────
    if cli.dry_run {
        info!("DRY RUN — no files written");
        generator::generate_dry(&resources)?;
    } else {
        std::fs::create_dir_all(&cli.output)?;
        info!("Writing .tf files to {}", cli.output.display());
        generator::generate_all(&resources, &cli.output)?;

        if cli.import_script {
            generator::imports::generate(&resources, &cli.output)?;
            let instances_dir = cli.output.join("instances");
            generator::imports::generate_per_instance(&resources, &instances_dir)?;
        }
    }

    info!("Done. {} instances, {} SGs, {} VPCs, {} IAM roles",
        resources.instances.len(),
        resources.security_groups.len(),
        resources.vpcs.len(),
        resources.roles.len(),
    );

    Ok(())
}
