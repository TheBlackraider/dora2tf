use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use super::Resources;

/// Generate shared.tf import script (resources shared by 2+ instances).
pub fn generate_shared(
    resources: &Resources,
    shared_sg_ids: &HashSet<String>,
    shared_subnet_ids: &HashSet<String>,
    shared_vpc_ids: &HashSet<String>,
    output_dir: &Path,
) -> Result<()> {
    let mut script = String::from("#!/bin/bash\n");
    script.push_str("# Import shared resources — run from terraform/\n\n");

    for sg in &resources.security_groups {
        if shared_sg_ids.contains(&sg.id) {
            let sn = super::tf_name(&sg.name);
            script.push_str(&format!("terraform import aws_security_group.{} {}\n", sn, sg.id));
            for rule in &sg.ingress {
                let rn = format!("{}_ingress_{}_{}", sn, rule.protocol, rule.from_port);
                script.push_str(&format!(
                    "terraform import aws_security_group_rule.{} {}_ingress_{}_{}\n",
                    rn, sg.id, rule.protocol, rule.from_port
                ));
            }
        }
    }

    for vpc in &resources.vpcs {
        if shared_vpc_ids.contains(&vpc.id) {
            let vn = super::tf_name(&vpc.name);
            script.push_str(&format!("terraform import aws_vpc.{} {}\n", vn, vpc.id));
            for sub in &vpc.subnets {
                if shared_subnet_ids.contains(&sub.id) {
                    let sn = super::tf_name(&sub.name);
                    script.push_str(&format!("terraform import aws_subnet.{} {}\n", sn, sub.id));
                }
            }
        }
    }

    for role in &resources.roles {
        let rn = super::tf_name(&role.name);
        script.push_str(&format!("terraform import aws_iam_role.{} {}\n", rn, role.name));
    }

    let path = output_dir.join("shared_import.sh");
    write_script(&path, &script)?;
    Ok(())
}

/// Generate per-instance import script.
/// Imports exclusive resources (inline) + the instance itself.
/// Shared resources are imported via shared_import.sh.
pub fn generate_per_instance(
    inst: &crate::scanner::ec2::Ec2Instance,
    all_sgs: &[crate::scanner::sg::SecurityGroup],
    all_vpcs: &[crate::scanner::vpc::VpcInfo],
    shared_sg_ids: &HashSet<String>,
    shared_subnet_ids: &HashSet<String>,
    shared_vpc_ids: &HashSet<String>,
    instances_dir: &Path,
) -> Result<()> {
    let inst_name = super::tf_name(&inst.name);
    let mut script = String::from("#!/bin/bash\n");
    script.push_str(&format!("# Import for: {} ({})\n", inst.name, inst.id));
    script.push_str("# Run from: terraform/instances/\n");
    script.push_str("# Run shared_import.sh first if shared resources changed\n\n");

    // Exclusive SGs (inline in this file)
    for sg_id in &inst.security_groups {
        if !shared_sg_ids.contains(sg_id) {
            if let Some(sg) = all_sgs.iter().find(|s| &s.id == sg_id) {
                let sn = super::tf_name(&sg.name);
                script.push_str(&format!("terraform import aws_security_group.{} {}\n", sn, sg.id));
                for rule in &sg.ingress {
                    let rn = format!("{}_ingress_{}_{}", sn, rule.protocol, rule.from_port);
                    script.push_str(&format!(
                        "terraform import aws_security_group_rule.{} {}_ingress_{}_{}\n",
                        rn, sg.id, rule.protocol, rule.from_port
                    ));
                }
            }
        }
    }

    // Exclusive VPC + subnet
    if !inst.subnet_id.is_empty() {
        for vpc in all_vpcs {
            for sub in &vpc.subnets {
                if sub.id == inst.subnet_id {
                    if !shared_vpc_ids.contains(&vpc.id) {
                        let vn = super::tf_name(&vpc.name);
                        script.push_str(&format!("terraform import aws_vpc.{} {}\n", vn, vpc.id));
                    }
                    if !shared_subnet_ids.contains(&sub.id) {
                        let sn = super::tf_name(&sub.name);
                        script.push_str(&format!("terraform import aws_subnet.{} {}\n", sn, sub.id));
                    }
                }
            }
        }
    }

    // The instance itself
    script.push_str(&format!("terraform import aws_instance.{} {}\n", inst_name, inst.id));

    let filename = format!("{}_import.sh", inst_name);
    let path = instances_dir.join(filename);
    write_script(&path, &script)?;
    Ok(())
}

fn write_script(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(path, perms);
        }
    }
    tracing::info!("  Wrote {} ({} bytes)", path.display(), content.len());
    Ok(())
}
