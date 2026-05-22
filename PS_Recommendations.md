Confluent Target Architecture & Governance Guardrails
Document Type: Target Architecture Specification
Scope: Confluent for Kubernetes (CFK) Platform Provisioning

Phase 2: Enterprise Governance Mandates
1. High Availability (HA) Enforcement
To prevent split-brain scenarios and ensure consensus availability during node failures, the KRaft quorum and broker counts must be strictly controlled.

Mandate: The replica count for both Kafka brokers and KRaft controllers must be 3 or greater.

2. Storage Security and Performance Standardization
Enterprise AWS deployments require both optimized I/O for heavy messaging loads and enterprise-grade data-at-rest encryption to meet security compliance.

Mandate: All persistent volume claims associated with Kafka and KRaft components must strictly specify the gp3-encrypted storage class to ensure AWS KMS integration. Requests for unencrypted gp3, legacy gp2, or unclassified storage are explicitly prohibited.

3. AWS Identity Integration (IRSA)
To maintain a zero-trust security posture, Confluent pods must utilize temporary, scoped AWS credentials rather than long-lived access keys.

Mandate: Both Kafka and KRaft components must explicitly define a valid AWS IAM role utilizing the [eks.amazonaws.com/role-arn](https://eks.amazonaws.com/role-arn) annotation within their pod templates.

4. Fault Tolerance and Node Distribution
To survive AWS Availability Zone (AZ) or individual underlying EC2 instance failures, stateful replicas must not be scheduled on the same physical or virtual hardware.

Mandate: Pod Anti-Affinity rules must be explicitly defined in the Custom Resource specifications under the podTemplate. The topology key must enforce separation across the underlying nodes.
5. Multi-Region Zone Distribution (Topology Spread)To achieve a true Multi-Region Cluster (MRC) architecture and ensure geographical fault tolerance, replica placement must be mathematically distributed across AWS Availability Zones (AZs) rather than relying solely on node-level anti-affinity.

Mandate: Both Kafka and KRaft components must explicitly define topologySpreadConstraints. The configuration must utilize the topology.kubernetes.io/zone topology key to enforce strict distribution across physical AZs.

6. Broker Rack AwarenessTo guarantee that Kafka's internal partition replica placement algorithm aligns with the physical cloud infrastructure, brokers must be inherently aware of their geographical deployment zones.

Mandate: Kafka components must explicitly define rack awareness mapping. The rack.topology specification must be set to topology.kubernetes.io/zone to sync the broker configuration with the underlying Kubernetes and AWS AZ labels.