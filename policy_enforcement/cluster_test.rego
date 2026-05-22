package main_test
import data.main.deny

# Mandate 1: High Availability
test_ha_pass if {
    res := deny with input as {"kind": "Kafka", "metadata": {"name": "test"}, "spec": {"replicas": 3}}
    not "Governance Violation: Cluster 'test' requires at least 3 replicas." in res
}

test_ha_fail_low_replicas if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "metadata": {"name": "test"}, "spec": {"replicas": 2}} 
                               with data.cluster_mandates.min_replicas as 3}
    "Governance Violation: Cluster 'test' requires at least 3 replicas." in res
}

test_controller_fail if {
    res := {msg | deny[msg] with input as {"kind": "KRaftController", "spec": {"replicas": 1}} 
                               with data.cluster_mandates.kraft_controller_nodes as 3}
    "Governance Violation: Kraft controller node count does not meet enterprise minimum." in res
}

# Mandate 2: Storage Security
test_storage_pass if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {"storageClass": {"name": "gp3-encrypted"}}} 
                               with data.cluster_mandates.storage_class as "gp3-encrypted"}
    not "Governance Violation: Cluster must use approved storage class: gp3-encrypted" in res
}

test_storage_fail if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {"storageClass": {"name": "gp2"}}} 
                               with data.cluster_mandates.storage_class as "gp3-encrypted"}
    "Governance Violation: Cluster must use approved storage class: gp3-encrypted" in res
}

# Mandate 4: Fault Tolerance and Node Distribution
test_pod_anti_affinity_pass if {
    res := deny with input as {
        "kind": "Kafka",
        "spec": {"podTemplate": {"affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": []}}}}
    }
    not "Governance Violation: Kafka requires podAntiAffinity to be defined in the podTemplate." in res
}

test_pod_anti_affinity_fail if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {}}}
    "Governance Violation: Kafka requires podAntiAffinity to be defined in the podTemplate." in res
}