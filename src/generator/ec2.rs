use anyhow::Result;
use std::fmt::Write;

use crate::scanner::ec2::Ec2Instance;

/// Generate a single instance with metadata comments about dependencies.
/// Used by --per-instance mode.
pub fn generate_one(inst: &Ec2Instance, output: &mut String) -> Result<()> {
    let name = super::tf_unique_name(&inst.name, &inst.id);

    // Header with metadata
    writeln!(output, "# ============================================================================")?;
    writeln!(output, "# Instance: {}  ({})", inst.name, inst.id)?;
    writeln!(output, "# Type: {}  |  AMI: {}  |  Private IP: {}", inst.instance_type, inst.ami, inst.private_ip)?;
    if !inst.subnet_id.is_empty() {
        writeln!(output, "# Subnet: {}", inst.subnet_id)?;
    }
    if !inst.security_groups.is_empty() {
        writeln!(output, "# Security Groups: {}", inst.security_groups.join(", "))?;
    }
    for vol in &inst.volumes {
        writeln!(output, "# Volume: {} ({}, {} GB, encrypted: {})", vol.id, vol.volume_type, vol.size_gb, vol.encrypted)?;
    }
    writeln!(output, "# ============================================================================\n")?;

    writeln!(output, "resource \"aws_instance\" \"{}\" {{", name)?;
    writeln!(output, "  ami           = \"{}\"", inst.ami)?;
    writeln!(output, "  instance_type = \"{}\"", inst.instance_type)?;

    if !inst.subnet_id.is_empty() {
        writeln!(output, "  subnet_id     = \"{}\"", inst.subnet_id)?;
    }
    if let Some(key) = &inst.key_name {
        writeln!(output, "  key_name      = \"{}\"", key)?;
    }
    if !inst.security_groups.is_empty() {
        writeln!(output, "  vpc_security_group_ids = [")?;
        for sg in &inst.security_groups {
            writeln!(output, "    \"{}\",", sg)?;
        }
        writeln!(output, "  ]")?;
    }

    if !inst.volumes.is_empty() {
        let vol = &inst.volumes[0];
        writeln!(output, "  root_block_device {{")?;
        writeln!(output, "    volume_type = \"{}\"", vol.volume_type)?;
        writeln!(output, "    volume_size = {}", vol.size_gb)?;
        writeln!(output, "    encrypted   = {}", vol.encrypted)?;
        writeln!(output, "    delete_on_termination = {}", vol.delete_on_termination)?;
        writeln!(output, "  }}")?;
    }

    writeln!(output, "  tags = {{")?;
    writeln!(output, "    Name        = \"{}\"", inst.name)?;
    writeln!(output, "    ManagedBy   = \"dora2tf\"")?;
    for (k, v) in &inst.tags {
        if k != "Name" && !v.is_empty() {
            writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
        }
    }
    writeln!(output, "  }}")?;
    writeln!(output, "}}\n")?;

    Ok(())
}

pub fn generate(instances: &[Ec2Instance], output: &mut String) -> Result<()> {
    for inst in instances {
        let name = super::tf_unique_name(&inst.name, &inst.id);

        writeln!(output, "resource \"aws_instance\" \"{}\" {{", name)?;
        writeln!(output, "  ami           = \"{}\"", inst.ami)?;
        writeln!(output, "  instance_type = \"{}\"", inst.instance_type)?;

        if !inst.subnet_id.is_empty() {
            writeln!(output, "  subnet_id     = \"{}\"", inst.subnet_id)?;
        }
        if let Some(key) = &inst.key_name {
            writeln!(output, "  key_name      = \"{}\"", key)?;
        }
        if !inst.security_groups.is_empty() {
            writeln!(output, "  vpc_security_group_ids = [")?;
            for sg in &inst.security_groups {
                writeln!(output, "    \"{}\",", sg)?;
            }
            writeln!(output, "  ]")?;
        }

        if !inst.volumes.is_empty() {
            let vol = &inst.volumes[0];
            writeln!(output, "  root_block_device {{")?;
            writeln!(output, "    volume_type = \"{}\"", vol.volume_type)?;
            writeln!(output, "    volume_size = {}", vol.size_gb)?;
            writeln!(output, "    encrypted   = {}", vol.encrypted)?;
            writeln!(output, "    delete_on_termination = {}", vol.delete_on_termination)?;
            writeln!(output, "  }}")?;
        }

        writeln!(output, "  tags = {{")?;
        writeln!(output, "    Name        = \"{}\"", inst.name)?;
        writeln!(output, "    ManagedBy   = \"dora2tf\"")?;
        for (k, v) in &inst.tags {
            if k != "Name" && !v.is_empty() {
                writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
            }
        }
        writeln!(output, "  }}")?;
        writeln!(output, "}}\n")?;
    }

    Ok(())
}
