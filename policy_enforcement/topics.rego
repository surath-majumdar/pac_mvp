package main

# Rule 3: Enterprise Topic Governance
deny contains msg if {
    input.kind == "KafkaTopic"
    global_mandate := data.global_limits.topic_partitions
    input.spec.partitions != global_mandate
    not is_within_approved_exception(input)
    
    msg := sprintf("Governance Violation: Topic '%v' requests %v partitions. The global mandate is exactly %v, and no valid ITSM exception authorizes this capacity.", [input.metadata.name, input.spec.partitions, global_mandate])
}

is_within_approved_exception(manifest) if {
    ticket := manifest.metadata.annotations["governance.confluent.io/approved-ticket"]
    approved_limit := fetch_snow_ticket_limit(ticket)
    manifest.spec.partitions == approved_limit
}

# Placeholder for future ServiceNow API integration
fetch_snow_ticket_limit(ticket) := limit if {
    # Future state: 
    # req := {"method": "GET", "url": sprintf("https://api.snow.internal/ticket/%v", [ticket])}
    # res := http.send(req)
    # limit := res.body.max_partitions
    
    # Hardcoded SNOW mock
    ticket == "CHG-00015"
    limit := 15
}