variable "relay_name" {
  description = "Relay name; suffix of the DNS name goat-relay-<name>."
  type        = string
}

variable "environment" {
  description = "Goatnet this relay serves."
  type        = string
}

variable "image_name" {
  description = "Glance image to boot, Ubuntu 24.04."
  type        = string
}

variable "flavor_name" {
  description = "Nova flavor. goat-relay's shard design assumes 8 vCPU (ADR 0712)."
  type        = string
}

variable "volume_size" {
  description = "Boot volume size in GB. Instances boot from a volume so flavors with no root disk work."
  type        = number
  default     = 40
}

variable "volume_type" {
  description = "Cinder volume type for the boot volume; null uses the cloud's default."
  type        = string
  default     = null
}

variable "network_name" {
  description = "Tenant network the relay's port sits on. It must have port security enabled."
  type        = string
}

variable "floating_ip_pool" {
  description = "External network that supplies the relay's floating IP."
  type        = string
}

variable "key_pair" {
  description = "Nova keypair for the ubuntu user."
  type        = string
}

variable "ssh_cidr_blocks" {
  description = "CIDRs allowed to SSH to the relay. Ansible connects over SSH."
  type        = list(string)
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id for the relay's DNS records."
  type        = string
}

variable "cloudflare_zone_name" {
  description = "Public zone name."
  type        = string
}

variable "relay_dns_prefix" {
  description = "Prefix of the per-relay DNS name."
  type        = string
  default     = "goat-relay"
}

variable "round_robin_dns" {
  description = "Add this relay to the round-robin record."
  type        = bool
  default     = true
}

variable "round_robin_dns_name" {
  description = "Name of the round-robin record, the enrolment apex."
  type        = string
  default     = "netbird"
}

variable "rathole_ingress_enabled" {
  description = "Open 443 and the rathole control port 2333."
  type        = bool
  default     = true
}

variable "rathole_cidr_blocks" {
  description = "CIDRs allowed to reach 443 and 2333."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "coturn_enabled" {
  description = "Open STUN on 3478."
  type        = bool
  default     = true
}

variable "coturn_turn_enabled" {
  description = "Open the TURN media range. coturn runs STUN-only unless coturn_turn_enabled is set in its role."
  type        = bool
  default     = false
}
