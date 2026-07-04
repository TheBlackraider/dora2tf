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
    let s = raw.to_lowercase().replace(['-', ' ', '.', '/'], "_");
    let s: String = s.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
    if s.is_empty() { "unnamed".into() } else { s }
}

/// Extract a short unique suffix from an AWS resource ID.
/// Example: "i-0abc123def456gh" → "i0abc123d"
///          "sg-0abc123d"       → "sg0abc123"
///          "vpc-0abc123d"      → "vpc0abc123"
///          "subnet-0abc123d"   → "sub0abc123"
///          "vol-0abc123d"      → "vol0abc123"
pub fn short_id(resource_id: &str) -> String {
    // Remove hyphens, take up to 10 chars (prefix + first 8 hex)
    let cleaned: String = resource_id.chars().filter(|c| *c != '-').collect();
    if cleaned.len() <= 10 {
        cleaned
    } else {
        cleaned[..10].to_string()
    }
}

/// Build a unique Terraform resource name guaranteed not to collide.
/// Combines `readable_name` with a short suffix from `resource_id`.
///
/// Example: tf_unique_name("web-server", "i-0abc123def456gh") → "web_server_i0abc123d"
pub fn tf_unique_name(readable: &str, resource_id: &str) -> String {
    let base = tf_name(readable);
    let suffix = short_id(resource_id);
    // Avoid duplicating prefix if name already starts with the ID prefix
    if base.starts_with(&suffix.to_lowercase()) {
        base
    } else {
        format!("{}_{}", base, suffix)
    }
}

/// Quote a tag key if it contains characters invalid in HCL identifiers.
/// Keys with `:`, `-`, `.`, `/`, spaces, or starting with a digit need quoting.
pub fn quote_tag_key(key: &str) -> String {
    let needs_quoting = key.is_empty()
        || key.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
        || key.contains(':')
        || key.contains('-')
        || key.contains('.')
        || key.contains('/')
        || key.contains(' ')
        || key.contains('@');
    if needs_quoting {
        format!("\"{}\"", key)
    } else {
        key.to_string()
    }
}
/// Format: {sg_name}_{direction}_{protocol}_{from_port}
/// Example: "web_sg_sg0abc123_ingress_tcp_80"
pub fn tf_rule_name(sg_name: &str, direction: &str, protocol: &str, from_port: i32) -> String {
    let proto = if protocol == "-1" { "all" } else { protocol };
    format!("{}_{}_{}_{}", sg_name, direction, proto, from_port)
}
