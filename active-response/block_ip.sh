#!/bin/bash
# active-response/block_ip.sh
# Wazuh active response: block a source IP at the iptables level when a
# correlated alert chain hits the configured rule level.
#
# Wazuh passes JSON on stdin with srcip, rule.id, rule.level.
# This script is registered in ossec.conf:
#
#   <command>
#     <name>block-ip</name>
#     <executable>block_ip.sh</executable>
#     <expect>srcip</expect>
#     <timeout_allowed>yes</timeout_allowed>
#   </command>
#   <active-response>
#     <command>block-ip</command>
#     <location>local</location>
#     <rules_id>100200,100201,100202</rules_id>
#     <timeout>3600</timeout>
#   </active-response>

set -euo pipefail

LOG="/var/ossec/logs/active-responses.log"
INPUT=$(cat)
ACTION=$(echo "$INPUT" | jq -r '.command')
SRCIP=$(echo "$INPUT" | jq -r '.parameters.alert.data.srcip // empty')
RULE_ID=$(echo "$INPUT" | jq -r '.parameters.alert.rule.id // empty')

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') block_ip[$$]: $*" >> "$LOG"
}

if [[ -z "$SRCIP" ]]; then
  log "no srcip in alert, skipping"
  exit 1
fi

# Skip RFC1918 and lab networks to avoid self-DoS
case "$SRCIP" in
  10.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|127.*)
    log "skipping internal IP $SRCIP"
    exit 0
    ;;
esac

case "$ACTION" in
  add)
    iptables -I INPUT -s "$SRCIP" -j DROP
    log "BLOCKED $SRCIP (rule $RULE_ID)"
    ;;
  delete)
    iptables -D INPUT -s "$SRCIP" -j DROP || true
    log "UNBLOCKED $SRCIP"
    ;;
  *)
    log "unknown action: $ACTION"
    exit 1
    ;;
esac
