package main_test
import data.main.deny

test_topic_partitions_pass if {
    mock_topic := {"kind": "KafkaTopic", "metadata": {"name": "compliant"}, "spec": {"partitions": 6}}
    count({msg | deny[msg] with input as mock_topic with data.global_limits.topic_partitions as 6}) == 0
}

test_topic_itsm_override_pass if {
    mock_topic := {
        "kind": "KafkaTopic",
        "metadata": {"name": "high-throughput", "annotations": {"governance.confluent.io/approved-ticket": "CHG-00015"}},
        "spec": {"partitions": 15}
    }
    
    count({msg | deny[msg] with input as mock_topic 
                               with data.global_limits.topic_partitions as 6}) == 0
}

test_config_has_topic_partitions_key if {
    mock_config := {"topic_partitions": 6}
    val := data.global_limits.topic_partitions with data.global_limits as mock_config
    is_number(val)
}