*** Settings ***
Library           SSHLibrary
Library           Collections
Library           String

*** Variables ***
${COLLECTOR_TOKEN}    cms_v1_RobotTestCollectorBearerToken1234567890abcd

*** Test Cases ***
Add Central Monitoring Collector Module
    ${output}    ${rc} =    Execute Command
    ...    add-module ${IMAGE_URL} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    ${module_info} =    Evaluate    json.loads('''${output}''')    json
    Set Suite Variable    ${MODULE_ID}    ${module_info['module_id']}
    Should Start With    ${MODULE_ID}    central-monitoring-collector

Verify Unconfigured Collector State
    ${output}    ${rc} =    Execute Command
    ...    api-cli run module/${MODULE_ID}/get-configuration --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    ${cfg} =    Evaluate    json.loads('''${output}''')    json
    Should Be Equal    ${cfg['configured']}    ${False}
    Should Be Equal    ${cfg['health']['alloy_status']}    disabled

Configure Collector Module And Start Alloy Services
    ${payload} =    Catenate    SEPARATOR=
    ...    {"hub_url":"https://monitoring.msp.example.com",
    ...    "auth_token":"${COLLECTOR_TOKEN}",
    ...    "auth_token_unchanged":false,
    ...    "customer":"robot-tenant",
    ...    "site":"hq",
    ...    "collect_local_ns8":true,
    ...    "enable_syslog_receiver":true,
    ...    "syslog_port":5514,
    ...    "wal_max_disk_mb":1024,
    ...    "tls_skip_verify":false}
    ${output}    ${rc} =    Execute Command
    ...    api-cli run module/${MODULE_ID}/configure-module --data '${payload}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    ${res} =    Evaluate    json.loads('''${output}''')    json
    Should Be Equal    ${res['status']}    ok

Save QNAP NAS And RFC 3805 Printer LAN Targets With Live Reload
    ${qnap} =    Catenate    SEPARATOR=
    ...    {"name":"QNAP Backup NAS","enabled":true,"target_type":"snmp",
    ...    "device_role":"snmp-nas","host":"192.168.50.20","port":161,
    ...    "snmp_module":"qnap","snmp_version":"v2c","snmp_community":"nas-ro"}
    ${out1}    ${rc1} =    Execute Command
    ...    api-cli run module/${MODULE_ID}/save-local-target --data '${qnap}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc1}    0

    ${printer} =    Catenate    SEPARATOR=
    ...    {"name":"Floor Printer","enabled":true,"target_type":"snmp",
    ...    "device_role":"snmp-printer","host":"192.168.50.30","port":161,
    ...    "snmp_module":"printer","snmp_version":"v2c","snmp_community":"prt-ro"}
    ${out2}    ${rc2} =    Execute Command
    ...    api-cli run module/${MODULE_ID}/save-local-target --data '${printer}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc2}    0
    ${prt_saved} =    Evaluate    json.loads('''${out2}''')    json
    Set Suite Variable    ${PRINTER_TARGET_ID}    ${prt_saved['id']}

List And Delete LAN Targets With Redacted Secrets
    ${list_out}    ${rc} =    Execute Command
    ...    api-cli run module/${MODULE_ID}/list-local-targets --data '{}'
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    Should Not Contain    ${list_out}    nas-ro
    Should Not Contain    ${list_out}    prt-ro

    ${del_out}    ${del_rc} =    Execute Command
    ...    api-cli run module/${MODULE_ID}/delete-local-target --data '{"id":"${PRINTER_TARGET_ID}"}'
    ...    return_rc=True
    Should Be Equal As Integers    ${del_rc}    0

Verify Cluster-Wide NS8 Textfile Metrics Output
    ${prom_out}    ${rc} =    Execute Command
    ...    runagent -m ${MODULE_ID} ~/.config/bin/collect-ns8-metrics && head -n 40 /home/${MODULE_ID}/.config/state/textfile/ns8.prom
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    Should Contain    ${prom_out}    ns8_container_info

Remove Central Monitoring Collector Module
    ${output}    ${rc} =    Execute Command
    ...    remove-module --no-preserve ${MODULE_ID}
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
