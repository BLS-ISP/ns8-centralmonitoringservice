*** Settings ***
Library           SSHLibrary
Suite Setup       Connect To NS8 Leader Node
Suite Teardown    Close All Connections

*** Variables ***
${NODE_ADDR}      127.0.0.1
${SSH_PORT}       22
${SSH_USER}       root
${SSH_KEYFILE}    /id_rsa
${IMAGE_URL}      ghcr.io/nethserver/central-monitoring-collector:latest

*** Keywords ***
Connect To NS8 Leader Node
    Open Connection    ${NODE_ADDR}    port=${SSH_PORT}    timeout=60s
    Login With Public Key    ${SSH_USER}    ${SSH_KEYFILE}
