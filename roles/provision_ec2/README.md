# Provision EC2 Role

This role provisions Windows EC2 instances configured for SSH-only access (no WinRM) and integrates with HashiCorp Vault for secure credential storage.

## Features

- **Windows Server 2019/2022 Support**: Launches Windows images with opinionated hardening.
- **SSH-Only Access**: Configures OpenSSH Server via a PowerShell user data template (renders from `templates/user_data.ps1.j2`).
- **EC2 Key Pair Management**: Creates or reuses key pairs, storing material locally and optionally in Vault.
- **Route53 Integration (optional)**: Creates DNS A records with propagation checks when enabled.
- **Elastic IP Management**: Optionally allocates or re-associates an Elastic IP to provide a static public address.
- **Volume Tagging**: Tags the root EBS volume with a consistent name for easier tracing.
- **Vault Integration**: Stores SSH private keys securely in HashiCorp Vault KV v2 using AppRole auth.
- **Custom Facts**: Publishes persistent local facts on Windows instances so downstream playbooks can inspect provisioning metadata.
- **Security Groups**: Creates a per-instance security group seeded with SSH access.

## Requirements

Install the following collections (see `requirements.yml`):

- `amazon.aws`
- `community.crypto`
- `community.hashi_vault`
- `ansible.windows`
- `community.windows`

You will also need:

- AWS credentials (environment, profile, or AWX credential).
- Vault AppRole credentials when `vault_addr`/`vault_url` are provided.
- SSH connectivity to the Windows host (OpenSSH) for post-provision facts.

## Variables

The role defines argument specifications and additional runtime validation. The most important variables are summarised below. See `defaults/main.yml` for exhaustive defaults.

### Required

```yaml
provision_ec2_aws_region: us-east-1
provision_ec2_name_tag: my-sql-server
```

### Commonly Adjusted

```yaml
# Instance specification
provision_ec2_instance_type: t3.large
provision_ec2_image_id: ami-05b00365623a86bd3

# Networking (discovered if omitted)
provision_ec2_aws_vpc_id: vpc-0123456789abcdef0
provision_ec2_aws_subnet_id: subnet-0123456789abcdef0

# Security group
provision_ec2_security_group_name: ansible-windows-sg
provision_ec2_security_group_rules:
  - { proto: tcp, ports: [22],   cidr_ip: "0.0.0.0/0", rule_desc: "SSH" }
  - { proto: tcp, ports: [3389], cidr_ip: "0.0.0.0/0", rule_desc: "RDP" }
  - { proto: tcp, ports: [1433], cidr_ip: "10.0.0.0/8", rule_desc: "SQL" }

# Route53
provision_ec2_configure_route53: true
provision_ec2_route53_zone: Z1234567890ABC
provision_ec2_route53_record_name: sql01.example.com

# Elastic IP
# provision_eip_allocation_id: eipalloc-0123456789abcdef0  # reuse existing allocation
```

### Vault Options

```yaml
vault_addr: https://vault.example.com:8200
vault_role_id: "{{ lookup('env', 'VAULT_ROLE_ID') }}"
vault_secret_id: "{{ lookup('env', 'VAULT_SECRET_ID') }}"
vault_kv_mount: secret
vault_ssh_path: windows/ssh/sql01
vault_verify: true
vault_ca_cert_env_var: VAULT_CA_CERT_PEM
```

Set `vault_addr`/`vault_url`, `vault_role_id`, and `vault_secret_id` to enable Vault storage. The role automatically loads values from environment variables when present.

### Customisation Flags

```yaml
provision_set_custom_facts: true        # Push Ansible facts to the instance
provision_ec2_configure_route53: false      # Skip DNS registration by default
provision_ec2_provision_control_host: localhost       # Host performing AWS/Vault/SSH key actions
provision_eip_allocation_id: ""         # Reuse an existing Elastic IP allocation (optional)


### Security Groups

Every run creates a dedicated security group named after the instance (sanitised with a `-sg` suffix). Provisioning opens inbound TCP/22 from `0.0.0.0/0`, and downstream roles can append additional access rules automatically.

### Naming Consistency

The role derives a reusable slug from `provision_ec2_name_tag` and applies it to related AWS resources:

- EC2 key pair: `<instance-slug>-key`
- Security group: `<instance-slug>-sg`
- Local private key path: `~/.ssh/<instance-slug>-key.pem`

You can override any name explicitly (for example `provision_ec2_keypair_name`) when required, but the defaults keep resources easy to identify across playbooks.

## Task Flow

1. **validate.yml**: Enforces required inputs.
2. **context.yml**: Builds derived values (key names, Vault paths, etc.).
3. **discover.yml**: Discovers default VPC/subnet when omitted.
4. **keypair.yml**: Generates or reuses SSH keys on the control host and imports the AWS key pair.
5. **security_group.yml**: Creates the security group with opinionated rules.
6. **instance.yml**: Launches the EC2 instance with the rendered PowerShell bootstrap script.
7. **route53.yml** *(optional)*: Creates DNS records and waits for propagation.
8. **vault_store_ssh.yml**: Stores key material in Vault when credentials are available.
9. **facts.yml** *(optional)*: Publishes persistent Windows facts via OpenSSH.
10. **summary.yml**: Outputs consolidated provisioning results and fails if the instance is not running.

## Outputs

The role registers the following facts for downstream usage:

- `provision_ec2_keypair_info`: Local/AWS key pair metadata (fingerprint, key material).
- `provision_ec2_instance_info`: Instance identifiers, IPs, and state.
- `provision_ec2_route53_info`: DNS record metadata when Route53 integration runs.
- `vault_ssh_stored`: Boolean indicating whether the SSH secret was successfully verified in Vault.
- `vault_ssh_path_full`: Fully-qualified KV path of the stored secret (or `n/a` when disabled).

## Usage

Example playbook (`01_provision_ec2.yml`):

```yaml
---
- name: Provision Windows EC2 instance with SSH access
  hosts: localhost
  gather_facts: false
  connection: local

  roles:
    - role: provision_ec2
      vars:
        vault_auth_mount_point: approle
```

Add additional variables via inventory, extra vars, or AWX job template inputs.

## Troubleshooting

- **Vault storage fails**: Ensure the AppRole has write/read access to the target KV path and that TLS certificates are trusted (`vault_ca_cert_env_var`).
- **SSH not accessible**: Review console output or the bootstrap log (`C:\debug\user_data_bootstrap.log`) to confirm the user data script completed successfully.
- **Route53 delays**: Increase `provision_ec2_route53_provision_ec2_dns_check_retries`/`provision_ec2_route53_provision_ec2_dns_check_delay` or disable propagation waits via `provision_ec2_route53_wait_for_propagation`.
- **Custom facts missing**: Confirm `provision_set_custom_facts` is true and that OpenSSH connectivity from the control node to the instance works.
