# Troubleshooting

Start here: `tail -f /var/ossec/logs/integrations.log` and re-run the script by hand with `debug`
(see [TESTING.md](TESTING.md) section 2).

| Symptom | Cause | Fix |
|---|---|---|
| Manager will not start after copying rules | Duplicate rule ID, or `<if_sid>` pointing at a rule that does not exist | `wazuh-analysisd -t` prints the offender. Linux ignore rules are 100630+ in this package for that reason; keep `optional/windows-process-ignore.xml` out unless rule 100691 exists |
| Script never runs | The alert's rule groups are not in the `<integration>` `<group>` list | Add the group, restart the manager. `<level>` filtering alone is a poor substitute |
| Script runs, nothing sent | No IOC extracted (private IPs only, unmonitored binary, unsupported group) | Run by hand with `debug`; the log says `No IOCs extracted for groups=...` |
| `OpenCTI unreachable` / rule 100211 | Wrong `hook_url`, firewall, OpenCTI down, HTTP 401/403 (bad token) | `curl` the URL from the manager with the token; check the log line for the HTTP code |
| Events arrive but no sighting | Below dedupe window; no identity; token lacks create rights; state file not writable | Log lines `sighting deduped`, `Could not resolve a sighting identity`, `Sighting failed: [...]`, `State file unavailable`. Check `/var/ossec/tmp` is writable by `wazuh` |
| `GRAPHQL_VALIDATION_FAILED` on sighting | Wrong field name (`count` instead of `attribute_count`) or schema differences between OpenCTI versions | The script uses `attribute_count`. If your version differs, compare against the schema in OpenCTI's GraphQL playground |
| Identity lookup returns nothing | On the lab OpenCTI, GraphQL *variables* inside filter literals returned nothing | Identity queries are inline literals here. Setting `WAZUH_IDENTITY_ID` avoids the lookup entirely |
| Sightings flood OpenCTI | Dedupe disabled or state file reset | Keep `SIGHTING_DEDUPE_SECONDS` > 0; do not delete `/var/ossec/tmp/opencti_integration_state*` while running |
| Output visible only on stdout | integratord discards stdout | Already handled: events are written to the Wazuh socket (`queue/sockets/queue`) |
| Self-signed HTTPS fails | Certificate verification (now on by default) | Install the CA, or set `"VERIFY_TLS": false` in the conf JSON for a lab |
| Same IOC alerts constantly | Normal: events are not deduplicated, sightings are | Tune with rule-level `frequency`/`timeframe` or raise `MIN_SCORE` |
| Many "domain" lookups for filenames | Command lines contain `name.ext` tokens | The script filters common file extensions; extend `NON_TLD_EXTENSIONS` if you see more |

## Bug log carried over from the lab writeup (all handled)

1. Sighting field is `attribute_count`, not `count`.
2. `objectLabel` is a flat list in some OpenCTI versions and edges/node in others: handled by `simplify_objectlist`.
3. Variable-based observable filters misbehaved on the lab OpenCTI. The IOC query uses OpenCTI's own `FilterGroup`
   variables (as in the stock Wazuh integration); identity helpers use inline literals.
4. `identityAdd` with variables returned `None`: inline mutation used, `systemAdd` as fallback.
5. Output must go to the Wazuh socket, not stdout.
6. Self-signed certificates: configurable instead of hard-disabled.
7. Dynamic identity lookup can fail: `WAZUH_IDENTITY_ID` setting plus cached ID.
8. Integration `<level>` too high hides low-level rules: use `<group>` lists.
