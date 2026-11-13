output "public_ip" {
  description = "Floating IP of the goat-relay"
  value       = openstack_networking_floatingip_v2.relay.address
}

output "instance_id" {
  description = "Nova instance id"
  value       = openstack_compute_instance_v2.relay.id
}

output "fixed_ip" {
  description = "Address on the relay's interface"
  value       = openstack_networking_port_v2.relay.all_fixed_ips[0]
}

output "relay_url" {
  description = "Full DNS hostname for the goat-relay"
  value       = "${local.dns_name}.${var.cloudflare_zone_name}"
}
