use anyhow::Result;
use std::collections::HashSet;
use std::fmt::Write;

use crate::scanner::ec2::Ec2Instance;
use crate::scanner::sg::SecurityGroup;
use crate::scanner::vpc::VpcInfo;

/// Generate one per-instance file.
/// Resources exclusive to this instance are defined inline.
/// Resources shared with other instances are referenced via aws_X.Y.id.
pub fn generate_one(
    inst: &Ec2Instance,
    all_sgs: &[SecurityGroup],
    all_vpcs: &[VpcInfo],
    shared_sg_ids: &HashSet<String>,
    shared_subnet_ids: &HashSet<String>,
    shared_vpc_ids: &HashSet<String>,
    output: &mut String,
) -> Result<()> {
    let inst_name = super::tf_name(&inst.name);

    writeln!(output, "# ============================================================================")?;
    writeln!(output, "# Instance: {}  ({})", inst.name, inst.id)?;
    writeln!(output, "# Type: {}  |  AMI: {}  |  Private IP: {}",
        inst.instance_type, inst.ami, inst.private_ip)?;
    writeln!(output, "# ============================================================================\n")?;

    // ── Exclusive SGs (only this instance uses them) → inline ──────────
    for sg_id in &inst.security_groups {
        if !shared_sg_ids.contains(sg_id) {
            if let Some(sg) = all_sgs.iter().find(|s| &s.id == sg_id) {
                let sn = super::tf_name(&sg.name);
                writeln!(output, "resource \"aws_security_group\" \"{}\" {{", sn)?;
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

                for rule in &sg.ingress {
                    let rn = format!("{}_ingress_{}_{}", sn, rule.protocol, rule.from_port);
                    writeln!(output, "resource \"aws_security_group_rule\" \"{}\" {{", rn)?;
                    writeln!(output, "  type              = \"ingress\"")?;
                    writeln!(output, "  from_port         = {}", rule.from_port)?;
                    writeln!(output, "  to_port           = {}", rule.to_port)?;
                    writeln!(output, "  protocol          = \"{}\"", rule.protocol)?;
                    writeln!(output, "  security_group_id = aws_security_group.{}.id", sn)?;
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

    // ── Exclusive VPC + subnet → inline ────────────────────────────────
    if !inst.subnet_id.is_empty() {
        for vpc in all_vpcs {
            for sub in &vpc.subnets {
                if sub.id == inst.subnet_id {
                    if !shared_vpc_ids.contains(&vpc.id) {
                        let vn = super::tf_name(&vpc.name);
                        writeln!(output, "resource \"aws_vpc\" \"{}\" {{", vn)?;
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
                    }
                    if !shared_subnet_ids.contains(&sub.id) {
                        let sn = super::tf_name(&sub.name);
                        let vn = super::tf_name(&vpc.name);
                        let vpc_ref = if shared_vpc_ids.contains(&vpc.id) {
                            format!("aws_vpc.{}", vn)
                        } else {
                            format!("aws_vpc.{}.id", vn)
                        };
                        // Wait, if VPC is inline we use .id, if shared we need the reference
                        // Actually: if VPC is defined in shared.tf, the reference is aws_vpc.name.id
                        // But here the VPC might be inline above — so we just defined it.
                        // Let me simplify: always reference as aws_vpc.name.id (works whether inline or shared)

                        writeln!(output, "resource \"aws_subnet\" \"{}\" {{", sn)?;
                        writeln!(output, "  vpc_id            = aws_vpc.{}.id", vn)?;
                        writeln!(output, "  cidr_block        = \"{}\"", sub.cidr)?;
                        writeln!(output, "  availability_zone = \"{}\"", sub.availability_zone)?;
                        writeln!(output, "  map_public_ip_on_launch = {}", sub.map_public_ip)?;
                        writeln!(output, "  tags = {{ Name = \"{}\" }}", sub.name)?;
                        writeln!(output, "}}\n")?;
                    }
                }
            }
        }
    }

    // ── The EC2 instance ───────────────────────────────────────────────
    writeln!(output, "resource \"aws_instance\" \"{}\" {{", inst_name)?;
    writeln!(output, "  ami           = \"{}\"", inst.ami)?;
    writeln!(output, "  instance_type = \"{}\"", inst.instance_type)?;

    if !inst.subnet_id.is_empty() {
        let ref_name = all_vpcs.iter()
            .flat_map(|v| &v.subnets)
            .find(|s| s.id == inst.subnet_id)
            .map(|s| format!("aws_subnet.{}.id", super::tf_name(&s.name)))
            .unwrap_or_else(|| format!("\"{}\"", inst.subnet_id));
        writeln!(output, "  subnet_id     = {}", ref_name)?;
    }
    if let Some(key) = &inst.key_name {
        writeln!(output, "  key_name      = \"{}\"", key)?;
    }
    if !inst.security_groups.is_empty() {
        writeln!(output, "  vpc_security_group_ids = [")?;
        for sg_id in &inst.security_groups {
            let ref_name = all_sgs.iter()
                .find(|s| &s.id == sg_id)
                .map(|s| format!("aws_security_group.{}.id", super::tf_name(&s.name)))
                .unwrap_or_else(|| format!("\"{}\"", sg_id));
            writeln!(output, "    {},", ref_name)?;
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
    for (k, v) in &inst.tags {
        if !v.is_empty() {
            writeln!(output, "    {} = \"{}\"", super::quote_tag_key(k), v)?;
        }
    }
    writeln!(output, "  }}")?;
    writeln!(output, "}}\n")?;

    Ok(())
}
