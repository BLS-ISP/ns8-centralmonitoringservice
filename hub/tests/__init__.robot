*** Settings ***
Library           SSHLibrary
Library           Collections
Suite Setup       Connect To Leader Node
Suite Teardown    Close All Connections

*** Variables ***
${NODE_ADDR}      127.0.0.1
${SSH_KEYFILE}    /id_rsa
${IMAGE_URL}      ghcr.io/nethserver/central-monitoring-hub:latest
${HUB_FQDN}       monitoring-hub.ns8.test

*** Keywords ***
Connect To Leader Node
    Open Connection    ${NODE_ADDR}
    Login With Public Key    root    ${SSH_KEYFILE}

Run Task
    [Arguments]    ${action}    ${data}={}
    ${output}    ${rc} =    Execute Command    api-cli run ${action} --data '${data}'    return_rc=True
    Should Be Equal As Integers    ${rc}    0    msg=Task ${action} failed: ${output}
    ${parsed} =    Evaluate    json.loads('''${output}''')    modules=json
    RETURN    ${parsed}
