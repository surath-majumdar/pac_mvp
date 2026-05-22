package main_test
import data.main.deny

# Mandate 6: Broker Rack Awareness
test_rack_topology_pass if {
    res := deny with input as {"kind": "Kafka", "spec": {"rack": {"topology": "topology.kubernetes.io/zone"}}}
    not "Governance Violation: Kafka rack.topology must be explicitly set to topology.kubernetes.io/zone." in res
}

test_rack_topology_fail if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {"rack": {"topology": "kubernetes.io/hostname"}}}}
    "Governance Violation: Kafka rack.topology must be explicitly set to topology.kubernetes.io/zone." in res
}

# Mandate 5: Multi-Region Zone Distribution
test_topology_spread_pass if {
    res := deny with input as {
        "kind": "KRaftController", 
        "spec": {"podTemplate": {"topologySpreadConstraints": [{"topologyKey": "topology.kubernetes.io/zone", "maxSkew": 1}]}}
    }
    not "Governance Violation: KRaftController must define topologySpreadConstraints utilizing the topology.kubernetes.io/zone key." in res
}

test_topology_spread_fail if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {"podTemplate": {"topologySpreadConstraints": [{"topologyKey": "kubernetes.io/hostname"}]}}}}
    "Governance Violation: Kafka must define topologySpreadConstraints utilizing the topology.kubernetes.io/zone key." in res
}