*** Settings ***
Library           SSHLibrary
Library           Collections
Library           String

*** Test Cases ***
Create Customer Tenant And Mint Ingest Token
    ${out} =    Run Task    module/${MODULE_ID}/save-tenant
    ...    {"customer": "acme-corp", "display_name": "Acme Corp GmbH", "sites": ["hq", "dc1"], "contact_emails": ["noc@acme.example.com"], "customer_portal_enabled": true, "portal_viewer_username": "acme-viewer", "portal_viewer_password": "AcmeViewerPassword!2026"}
    Should Be Equal As Strings    ${out}[status]    ok
    Should Match Regexp    ${out}[auth_token]    ^cms_v1_
    ${tenants} =    Run Task    module/${MODULE_ID}/list-tenants    {"page": 1, "page_size": 25}
    Should Be Equal As Integers    ${tenants}[pagination][total_items]    1

Generate Standalone Alloy Agent Onboarding Bundle
    ${bundle} =    Run Task    module/${MODULE_ID}/generate-agent-bundle
    ...    {"customer": "acme-corp", "site": "hq", "platform": "linux", "collector_id": "acme-linux-01", "enable_syslog": true, "syslog_port": 5514}
    Should Contain    ${bundle}[config_content]    acme-corp
    Should Not Contain    ${bundle}[config_content]    {{CUSTOMER}}

Save Central Blackbox And SNMP Targets
    ${bb} =    Run Task    module/${MODULE_ID}/save-target
    ...    {"name": "Acme Website", "enabled": true, "target_type": "blackbox", "customer": "acme-corp", "site": "hq", "device_role": "web", "scrape_interval": "60s", "endpoints": ["https://acme.example.com"], "blackbox_module": "http_2xx"}
    Should Be Equal As Strings    ${bb}[status]    ok
    ${snmp} =    Run Task    module/${MODULE_ID}/save-target
    ...    {"name": "Acme QNAP NAS", "enabled": true, "target_type": "snmp", "customer": "acme-corp", "site": "hq", "device_role": "snmp-nas", "scrape_interval": "60s", "endpoints": ["192.0.2.50:161"], "snmp_module": "qnap", "snmp_version": "v2c", "snmp_community": "public"}
    Should Be Equal As Strings    ${snmp}[status]    ok

Configure Alerting And Create Maintenance Silence
    ${alert_out} =    Run Task    module/${MODULE_ID}/configure-alerting
    ...    {"group_wait": "30s", "group_interval": "5m", "repeat_interval": "4h", "smarthost_email": {"enabled": true, "use_ns8_smarthost": true, "from_address": "alerts@ns8.test", "default_to_addresses": ["ops@ns8.test"], "send_resolved": true}, "webhook_psa": {"enabled": false, "url": "", "send_resolved": true}, "chat": {"teams_enabled": false, "slack_enabled": false, "slack_channel": "", "send_resolved": true}, "push": {"enabled": false, "provider": "none", "min_severity": "critical"}, "customer_email_routing": {"enabled": true, "min_severity": "critical", "send_resolved": true}, "enabled_rule_packs": ["ns8-cluster", "linux-node", "windows-node", "proxmox-ve", "blackbox-web-ssl", "snmp-network-ups"]}
    Should Be Equal As Strings    ${alert_out}[status]    ok
    ${silence} =    Run Task    module/${MODULE_ID}/create-silence
    ...    {"customer": "acme-corp", "site": "hq", "starts_at": "2030-01-01T00:00:00Z", "ends_at": "2030-01-01T04:00:00Z", "created_by": "robot-test", "comment": "Scheduled Patch Tuesday window"}
    Should Be Equal As Strings    ${silence}[status]    ok

Remove Central Monitoring Hub Module Cleanly
    ${rm} =    Execute Command    api-cli run remove-module --data '{"module_id": "${MODULE_ID}", "preserve_data": false}'    return_rc=False
