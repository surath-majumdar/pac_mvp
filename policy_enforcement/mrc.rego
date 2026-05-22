package main

# Mandate 6: Broker Rack Awareness
deny contains msg if {
    input.kind == "Kafka"
    not has_valid_rack_topology(input)
    msg := "Governance Violation: Kafka rack.topology must be explicitly set to topology.kubernetes.io/zone."
}

has_valid_rack_topology(manifest) if {
    manifest.spec.rack.topology == "topology.kubernetes.io/zone"
}

# Mandate 5: Multi-Region Zone Distribution (Topology Spread)
deny contains msg if {
    managed_kinds := {"Kafka", "KRaftController"}
    managed_kinds[input.kind]
    not has_valid_topology_spread(input)
    msg := sprintf("Governance Violation: %v must define topologySpreadConstraints utilizing the topology.kubernetes.io/zone key.", [input.kind])
}

has_valid_topology_spread(manifest) if {
    some i
    # CORRECTED PATH: Nested inside podTemplate
    manifest.spec.podTemplate.topologySpreadConstraints[i].topologyKey == "topology.kubernetes.io/zone"
}