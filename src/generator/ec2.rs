use anyhow::Result;
use std::collections::HashSet;
use std::fmt::Write;

use crate::scanner::ec2::Ec2Instance;
use crate::scanner::sg::SecurityGroup;
use crate::scanner::vpc::VpcInfo;

/// Generate a single self-contained instance file with all related resources inline.
/// Uses original tag names. No cross-file references — everything lives in this file.
pub fn generate_one(
    inst: &Ec2Instance,
    all_sgs: &[SecurityGroup],
    all_vpcs: &[VpcInfo],
    output: &mut String,
) -> Result<()> {
    let inst_name = super::tf_name(&inst.name);
    let mut written_sgs: HashSet<String> = HashSet::new();
    let mut written_subnets: HashSet<String> = HashSet::new();

    // ── Header ──────────────────────────────────────────────────────────
    writeln!(output, "# ============================================================================")?;
    writeln!(output, "# Instance: {}  ({})", inst.name, inst.id)?;
    writeln!(output, "# Type: {}  |  AMI: {}  |  Private IP: {}",
        inst.instance_type, inst.ami, inst.private_ip)?;
    writeln!(output, "# ============================================================================\n")?;

    // ── Security Groups used by this instance ──────────────────────────
    for sg_id in &inst.security_groups {
        if let Some(sg) = all_sgs.iter().find(|s| &s.id == sg_id) {
            if written_sgs.insert(sg.id.clone()) {
                writeln!(output, "resource \"aws_security_group\" \"{}\" {{",
                    super::tf_name(&sg.name))?;
                writeln!(output, "  name        = \"{}\"", sg.name)?;
                writeln!(output, "  description = \"{}\"", sg.description)?;
                writeln!(output, "  vpc_id      = \"{}\"", sg.vpc_id)?;
                writeln!(output, "  tags = {{")?;
                for (k, v) in &sg.tags {
                    if !v.is_empty() {
                        writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
                    }
                }
                writeln!(output, "  }}")?;
                writeln!(output, "}}\n")?;

                // Inline rules
                for rule in &sg.ingress {
                    let rn = format!("{}_ingress_{}_{}",
                        super::tf_name(&sg.name), rule.protocol, rule.from_port);
                    writeln!(output, "resource \"aws_security_group_rule\" \"{}\" {{", rn)?;
                    writeln!(output, "  type              = \"ingress\"")?;
                    writeln!(output, "  from_port         = {}", rule.from_port)?;
                    writeln!(output, "  to_port           = {}", rule.to_port)?;
                    writeln!(output, "  protocol          = \"{}\"", rule.protocol)?;
                    writeln!(output, "  security_group_id = aws_security_group.{}.id",
                        super::tf_name(&sg.name))?;
                    if !rule.cidr_blocks.is_empty() {
                        writeln!(output, "  cidr_blocks       = [")?;
                        for c in &rule.cidr_blocks {
                            writeln!(output, "    \"{}\",", c)?;
                        }
                        writeln!(output, "  ]")?;
                    }
                    writeln!(output, "}}\n")?;
                }
                writeln!(output)?;
            }
        }
    }

    // ── Subnet for this instance ────────────────────────────────────────
    if !inst.subnet_id.is_empty() {
        for vpc in all_vpcs {
            for sub in &vpc.subnets {
                if sub.id == inst.subnet_id && written_subnets.insert(sub.id.clone()) {
                    let vpc_name = super::tf_name(&vpc.name);
                    let sub_name = super::tf_name(&sub.name);

                    writeln!(output, "resource \"aws_vpc\" \"{}\" {{", vpc_name)?;
                    writeln!(output, "  cidr_block = \"{}\"", vpc.cidr)?;
                    writeln!(output, "  enable_dns_hostnames = true")?;
                    writeln!(output, "  tags = {{")?;
                    for (k, v) in &vpc.tags {
                        if !v.is_empty() {
                            writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
                        }
                    }
                    writeln!(output, "  }}")?;
                    writeln!(output, "}}\n")?;

                    writeln!(output, "resource \"aws_subnet\" \"{}\" {{", sub_name)?;
                    writeln!(output, "  vpc_id            = aws_vpc.{}.id", vpc_name)?;
                    writeln!(output, "  cidr_block        = \"{}\"", sub.cidr)?;
                    writeln!(output, "  availability_zone = \"{}\"", sub.availability_zone)?;
                    writeln!(output, "  map_public_ip_on_launch = {}", sub.map_public_ip)?;
                    writeln!(output, "  tags = {{")?;
                    writeln!(output, "    Name = \"{}\"", sub.name)?;
                    writeln!(output, "  }}")?;
                    writeln!(output, "}}\n")?;
                }
            }
        }
    }

    // ── The EC2 instance itself ─────────────────────────────────────────
    writeln!(output, "resource \"aws_instance\" \"{}\" {{", inst_name)?;
    writeln!(output, "  ami           = \"{}\"", inst.ami)?;
    writeln!(output, "  instance_type = \"{}\"", inst.instance_type)?;

    if !inst.subnet_id.is_empty() {
        // Find subnet name for reference
        let sub_ref = all_vpcs.iter()
            .flat_map(|v| &v.subnets)
            .find(|s| s.id == inst.subnet_id)
            .map(|s| format!("aws_subnet.{}.id", super::tf_name(&s.name)))
            .unwrap_or_else(|| format!("\"{}\"", inst.subnet_id));
        writeln!(output, "  subnet_id     = {}", sub_ref)?;
    }
    if let Some(key) = &inst.key_name {
        writeln!(output, "  key_name      = \"{}\"", key)?;
    }
    if !inst.security_groups.is_empty() {
        writeln!(output, "  vpc_security_group_ids = [")?;
        for sg_id in &inst.security_groups {
            let sg_ref = all_sgs.iter()
                .find(|s| &s.id == sg_id)
                .map(|s| format!("aws_security_group.{}.id", super::tf_name(&s.name)))
                .unwrap_or_else(|| format!("\"{}\"", sg_id));
            writeln!(output, "    {},", sg_ref)?;
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
    writeln!(output, "    Name = \"{}\"", inst.name)?;
    for (k, v) in &inst.tags {
        if k != "Name" && !v.is_empty() {
            writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
        }
    }
    writeln!(output, "  }}")?;
    writeln!(output, "}}\n")?;

    Ok(())
}

/// Generate all instances together (shared file mode).
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
