*** Settings ***
Library           SSHLibrary
Library           Collections

*** Variables ***
${HUB_FQDN}       monitoring-hub.ns8.test

*** Test Cases ***
Install Central Monitoring Hub Module
    ${resp} =    Run Task    add-module    {"image": "${IMAGE_URL}", "node": 1}
    ${module_id} =    Get From Dictionary    ${resp}    module_id
    Should Not Be Empty    ${module_id}
    Set Global Variable    ${MODULE_ID}    ${module_id}

Verify Unconfigured Initial State
    ${cfg} =    Run Task    module/${MODULE_ID}/get-configuration    {}
    Should Be Equal    ${cfg}[configured]    ${False}
    Should Be Equal As Strings    ${cfg}[storage_mode]    local

Configure Central Monitoring Hub In Local Mode
    ${cfg_out} =    Run Task    module/${MODULE_ID}/configure-module
    ...    {"host": "${HUB_FQDN}", "lets_encrypt": false, "http2https": true, "retention_days": 30, "retention_size_gb": 50, "loki_retention_days": 30, "backup_include_tsdb": false, "storage_mode": "local", "grafana_admin_password": "Ns8RobotAdminPassword!2026"}
    Should Be Equal As Strings    ${cfg_out}[status]    ok
    Should Be Equal As Strings    ${cfg_out}[grafana_url]    https://${HUB_FQDN}

Verify Configured Overview And Redacted Configuration
    ${cfg} =    Run Task    module/${MODULE_ID}/get-configuration    {}
    Should Be Equal    ${cfg}[configured]    ${True}
    Should Be Equal    ${cfg}[has_grafana_admin_password]    ${True}
    ${ov} =    Run Task    module/${MODULE_ID}/get-overview    {}
    Should Be Equal    ${ov}[configured]    ${True}
    Should Be Equal As Strings    ${ov}[storage_mode]    local
    Should Be Equal As Strings    ${ov}[components][thanos_query]    disabled
