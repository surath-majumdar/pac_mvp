package main_test
import data.main.deny

# Mandate 6: Region Enforcement
test_region_pass if {
    res := deny with input as {"kind": "Kafka", "spec": {"provider": {"region": "us-west-2"}}}
    not "Governance Violation: Cluster deployment restricted to us-west-2 region." in res
}

test_region_fail if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {"provider": {"region": "us-east-1"}}}}
    "Governance Violation: Cluster deployment restricted to us-west-2 region." in res
}

# Mandate 3: AWS Identity Integration (IRSA)
test_irsa_pass if {
    res := deny with input as {
        "kind": "Kafka",
        "spec": {"podTemplate": {"annotations": {"eks.amazonaws.com/role-arn": "arn:aws:iam::111122223333:role/kafka-role"}}}
    }
    not "Governance Violation: Kafka must define the eks.amazonaws.com/role-arn annotation for IRSA." in res
}

test_irsa_fail if {
    res := {msg | deny[msg] with input as {"kind": "KRaftController", "spec": {}}}
    "Governance Violation: KRaftController must define the eks.amazonaws.com/role-arn annotation for IRSA." in res
}

test_storage_pass if {
    res := {msg | deny[msg] with input as {"kind": "Kafka", "spec": {"storageClass": {"name": "gp3-encrypted"}}} 
                               with data.cluster_mandates.storage_class as "gp3-encrypted"}
    not "Governance Violation: Cluster must use approved storage class: gp3-encrypted" in res
}