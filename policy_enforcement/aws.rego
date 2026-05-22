package main

# Existing Rule: Region Enforcement
deny contains msg if {
    input.kind == "Kafka"
    input.spec.provider.region != "us-west-2"
    msg := "Governance Violation: Cluster deployment restricted to us-west-2 region."
}

# Mandate 3: AWS Identity Integration (IRSA)
deny contains msg if {
    managed_kinds := {"Kafka", "KRaftController"}
    managed_kinds[input.kind]
    not has_irsa_annotation(input)
    msg := sprintf("Governance Violation: %v must define the eks.amazonaws.com/role-arn annotation for IRSA.", [input.kind])
}

# FIX: Renamed 'input' to 'manifest' in the function signature
has_irsa_annotation(manifest) if {
    manifest.spec.podTemplate.annotations["eks.amazonaws.com/role-arn"]
}