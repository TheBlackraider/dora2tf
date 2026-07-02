use anyhow::Result;
use aws_sdk_ec2::Client;

#[derive(Debug, Clone)]
pub struct Ec2Instance {
    pub id:             String,
    pub name:           String,
    pub instance_type:  String,
    pub ami:            String,
    pub subnet_id:      String,
    pub private_ip:     String,
    pub security_groups: Vec<String>,
    pub key_name:       Option<String>,
    pub volumes:        Vec<AttachedVolume>,
    pub tags:           std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct AttachedVolume {
    pub id:          String,
    pub device_name: String,
    pub size_gb:     i32,
    pub volume_type: String,
    pub encrypted:   bool,
    pub delete_on_termination: bool,
}

pub async fn scan_instances(client: &Client) -> Result<Vec<Ec2Instance>> {
    let resp = client.describe_instances().send().await?;
    let mut instances = Vec::new();

    for reservation in resp.reservations() {
        for inst in reservation.instances() {
            let name = inst
                .tags()
                .iter()
                .find(|t| t.key().map(|k| k == "Name").unwrap_or(false))
                .and_then(|t| t.value().map(|s| s.to_string()))
                .unwrap_or_else(|| inst.instance_id().unwrap_or("unknown").into());

            let volumes: Vec<AttachedVolume> = inst
                .block_device_mappings()
                .iter()
                .map(|bdm| {
                    let ebs = bdm.ebs();
                    AttachedVolume {
                        id:          ebs.and_then(|v| v.volume_id()).map(|s| s.to_string()).unwrap_or_default(),
                        device_name: bdm.device_name().map(|s| s.to_string()).unwrap_or_default(),
                        size_gb:     0,  // full volume details require describe_volumes
                        volume_type: "gp2".into(),
                        encrypted:   false,
                        delete_on_termination: ebs.and_then(|v| v.delete_on_termination()).unwrap_or(true),
                    }
                })
                .collect();

            instances.push(Ec2Instance {
                id:             inst.instance_id().map(|s| s.to_string()).unwrap_or_default(),
                name,
                instance_type:  inst.instance_type().map(|t| t.as_str().to_string()).unwrap_or_else(|| "t3.micro".into()),
                ami:            inst.image_id().map(|s| s.to_string()).unwrap_or_default(),
                subnet_id:      inst.subnet_id().map(|s| s.to_string()).unwrap_or_default(),
                private_ip:     inst.private_ip_address().map(|s| s.to_string()).unwrap_or_default(),
                security_groups: inst.security_groups().iter()
                    .filter_map(|g| g.group_id().map(|s| s.to_string()))
                    .collect(),
                key_name:       inst.key_name().map(|s| s.to_string()),
                volumes,
                tags:           inst.tags().iter()
                    .filter_map(|t| { let k = t.key()?; let v = t.value().unwrap_or_default(); Some((k.to_string(), v.to_string())) })
                    .collect(),
            });
        }
    }

    Ok(instances)
}
