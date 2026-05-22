package main

# Rule 1: Min Replicas
deny contains msg if { 
    input.kind == "Kafka"
    min_rep := data.cluster_mandates.min_replicas
    input.spec.replicas < min_rep
    msg := sprintf("Governance Violation: Cluster '%v' requires at least %v replicas.", [input.metadata.name, min_rep])
}

# Rule 2: Controller Count
deny contains msg if {
    input.kind == "KRaftController"
    input.spec.replicas < data.cluster_mandates.kraft_controller_nodes
    msg := "Governance Violation: Kraft controller node count does not meet enterprise minimum."
}

# Rule 3: Storage Class Enforcement
deny contains msg if {
    input.kind == "Kafka"
    storage_req := data.cluster_mandates.storage_class
    input.spec.storageClass.name != storage_req
    msg := sprintf("Governance Violation: Cluster must use approved storage class: %v", [storage_req])
}

# Mandate 4: Fault Tolerance and Node Distribution
deny contains msg if {
    input.kind == "Kafka"
    not has_pod_anti_affinity(input)
    msg := sprintf("Governance Violation: %v requires podAntiAffinity to be defined in the podTemplate.", [input.kind])
}

has_pod_anti_affinity(manifest) if {
    manifest.spec.podTemplate.affinity.podAntiAffinity
}