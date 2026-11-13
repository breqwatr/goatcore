# One goat-relay on OpenStack: the counterpart of ../goat-relay for clouds
# without EC2. Same DNS names and ports; Ansible reaches it over SSH.

terraform {
  required_version = ">= 1.6"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 3.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

locals {
  resource_name = "${var.environment}-goat-relay-${var.relay_name}"
  dns_name      = var.relay_name != "" ? "${var.relay_dns_prefix}-${var.relay_name}" : var.relay_dns_prefix

  anywhere = ["0.0.0.0/0"]

  # protocol, first port, last port, sources
  rule_sets = concat(
    [
      { name = "relay-tcp", protocol = "tcp", min = 33073, max = 33073, cidrs = local.anywhere },
      { name = "relay-udp", protocol = "udp", min = 33073, max = 33073, cidrs = local.anywhere },
      { name = "ssh", protocol = "tcp", min = 22, max = 22, cidrs = var.ssh_cidr_blocks },
    ],
    var.rathole_ingress_enabled ? [
      { name = "rathole-https", protocol = "tcp", min = 443, max = 443, cidrs = var.rathole_cidr_blocks },
      { name = "rathole-control", protocol = "tcp", min = 2333, max = 2333, cidrs = var.rathole_cidr_blocks },
    ] : [],
    var.coturn_enabled ? [
      { name = "stun-udp", protocol = "udp", min = 3478, max = 3478, cidrs = local.anywhere },
      { name = "stun-tcp", protocol = "tcp", min = 3478, max = 3478, cidrs = local.anywhere },
    ] : [],
    var.coturn_enabled && var.coturn_turn_enabled ? [
      { name = "turn-media", protocol = "udp", min = 49152, max = 65535, cidrs = local.anywhere },
    ] : [],
  )

  rules = merge([
    for set in local.rule_sets : {
      for cidr in set.cidrs : "${set.name}-${cidr}" => merge(set, { cidr = cidr })
    }
  ]...)
}

data "openstack_images_image_v2" "relay" {
  name        = var.image_name
  most_recent = true
}

data "openstack_networking_network_v2" "tenant" {
  name = var.network_name
}

resource "openstack_networking_secgroup_v2" "relay" {
  name        = local.resource_name
  description = "goat-relay ${var.relay_name} on ${var.environment}"
}

resource "openstack_networking_secgroup_rule_v2" "relay" {
  for_each = local.rules

  security_group_id = openstack_networking_secgroup_v2.relay.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = each.value.protocol
  port_range_min    = each.value.min
  port_range_max    = each.value.max
  remote_ip_prefix  = each.value.cidr
}

resource "openstack_networking_secgroup_rule_v2" "icmp" {
  security_group_id = openstack_networking_secgroup_v2.relay.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "0.0.0.0/0"
}

resource "openstack_networking_port_v2" "relay" {
  name               = local.resource_name
  network_id         = data.openstack_networking_network_v2.tenant.id
  admin_state_up     = true
  security_group_ids = [openstack_networking_secgroup_v2.relay.id]
}

resource "openstack_compute_instance_v2" "relay" {
  name        = local.resource_name
  flavor_name = var.flavor_name
  key_pair    = var.key_pair
  # The keypair reaches the host through cloud-init; a config drive carries it
  # when the metadata service does not answer at first boot.
  config_drive = true

  block_device {
    uuid                  = data.openstack_images_image_v2.relay.id
    source_type           = "image"
    destination_type      = "volume"
    boot_index            = 0
    volume_size           = var.volume_size
    volume_type           = var.volume_type
    delete_on_termination = true
  }

  network {
    port = openstack_networking_port_v2.relay.id
  }

  lifecycle {
    ignore_changes = [block_device]
  }
}

resource "openstack_networking_floatingip_v2" "relay" {
  pool        = var.floating_ip_pool
  description = local.resource_name
}

resource "openstack_networking_floatingip_associate_v2" "relay" {
  floating_ip = openstack_networking_floatingip_v2.relay.address
  port_id     = openstack_networking_port_v2.relay.id
}

resource "cloudflare_record" "relay" {
  zone_id = var.cloudflare_zone_id
  name    = local.dns_name
  content = openstack_networking_floatingip_v2.relay.address
  type    = "A"
  ttl     = 60
  proxied = false
}

resource "cloudflare_record" "round_robin" {
  count   = var.round_robin_dns ? 1 : 0
  zone_id = var.cloudflare_zone_id
  name    = var.round_robin_dns_name
  content = openstack_networking_floatingip_v2.relay.address
  type    = "A"
  ttl     = 60
  proxied = false
}
