mod ec2;
mod iam;
pub mod imports;
mod sg;
mod vpc;

use std::fs;
use std::io::Write;
use std::path::Path;
use anyhow::Result;

/// Shared resource collection passed from scanner to generator.
#[derive(Default)]
pub struct Resources {
    pub instances:       Vec<crate::scanner::ec2::Ec2Instance>,
    pub security_groups: Vec<crate::scanner::sg::SecurityGroup>,
    pub vpcs:            Vec<crate::scanner::vpc::VpcInfo>,
    pub roles:           Vec<crate::scanner::iam::IamRole>,
}

/// Generate all .tf files from scanned resources.
pub fn generate_all(resources: &Resources, output_dir: &Path) -> Result<()> {
    let mut instances_tf    = String::new();
    let mut sg_tf           = String::new();
    let mut vpc_tf          = String::new();
    let mut iam_tf          = String::new();

    ec2::generate(&resources.instances, &mut instances_tf)?;
    sg::generate(&resources.security_groups, &mut sg_tf)?;
    vpc::generate(&resources.vpcs, &mut vpc_tf)?;
    iam::generate(&resources.roles, &mut iam_tf)?;

    write_if("ec2_instances.tf",    output_dir, &instances_tf)?;
    write_if("security_groups.tf",  output_dir, &sg_tf)?;
    write_if("vpc.tf",              output_dir, &vpc_tf)?;
    write_if("iam_roles.tf",        output_dir, &iam_tf)?;

    Ok(())
}

/// Dry run — print what would be generated.
pub fn generate_dry(resources: &Resources) -> Result<()> {
    println!("Would generate:");
    println!("  ec2_instances.tf    — {} instances",  resources.instances.len());
    println!("  security_groups.tf  — {} SGs",         resources.security_groups.len());
    println!("  vpc.tf              — {} VPCs",        resources.vpcs.len());
    println!("  iam_roles.tf        — {} IAM roles",   resources.roles.len());
    Ok(())
}

fn write_if(filename: &str, dir: &Path, content: &str) -> Result<()> {
    if content.trim().is_empty() {
        return Ok(());
    }
    let path = dir.join(filename);
    let mut f = fs::File::create(&path)?;
    f.write_all(content.as_bytes())?;
    tracing::info!("  Wrote {} ({} bytes)", path.display(), content.len());
    Ok(())
}

/// Normalize a tag Name to a Terraform-safe identifier.
pub fn tf_name(raw: &str) -> String {
    let s = raw.to_lowercase().replace(['-', ' ', '.'], "_");
    let s: String = s.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
    if s.is_empty() { "unnamed".into() } else { s }
}
