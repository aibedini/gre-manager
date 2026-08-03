# Graph Report - .  (2026-08-03)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 142 nodes · 545 edges · 11 communities (9 shown, 2 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `0f677cb6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]

## God Nodes (most connected - your core abstractions)
1. `ok()` - 32 edges
2. `info()` - 31 edges
3. `err()` - 27 edges
4. `gre-manager.sh script` - 24 edges
5. `require_root()` - 24 edges
6. `migrate_legacy_iran_conf()` - 22 edges
7. `setup_foreign()` - 21 edges
8. `audit_log()` - 20 edges
9. `interactive_add_iran_peer()` - 20 edges
10. `warn()` - 19 edges

## Surprising Connections (you probably didn't know these)
- `gre-manager.sh script` --calls--> `cli_export()`  [EXTRACTED]
  gre-manager.sh → gre-manager.sh  _Bridges community 2 → community 0_
- `gre-manager.sh script` --calls--> `cli_iran_peer_add()`  [EXTRACTED]
  gre-manager.sh → gre-manager.sh  _Bridges community 2 → community 4_
- `gre-manager.sh script` --calls--> `cli_node_add()`  [EXTRACTED]
  gre-manager.sh → gre-manager.sh  _Bridges community 2 → community 5_
- `gre-manager.sh script` --calls--> `doctor()`  [EXTRACTED]
  gre-manager.sh → gre-manager.sh  _Bridges community 2 → community 6_
- `gre-manager.sh script` --calls--> `usage()`  [EXTRACTED]
  gre-manager.sh → gre-manager.sh  _Bridges community 2 → community 1_

## Import Cycles
- None detected.

## Communities (11 total, 2 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.23
Nodes (32): ask(), ask_downtime_tolerance(), audit_log(), backup_restore_menu(), cli_export(), cli_iran_peer_remove(), cli_node_remove(), confirm() (+24 more)

### Community 2 - "Community 2"
Cohesion: 0.27
Nodes (18): gre-manager.sh script, apply_all(), apply_iran(), apply_iran_peer(), cli_import(), cli_iran_peer_apply(), cli_iran_peer_list(), cli_node_list() (+10 more)

### Community 3 - "Community 3"
Cohesion: 0.27
Nodes (15): run.sh script, add_de1(), add_nl1(), add_uk1(), assert(), assert_not(), bad(), build_sut() (+7 more)

### Community 4 - "Community 4"
Cohesion: 0.23
Nodes (16): apply_watchdog_config(), check_peer_collisions(), cli_iran_peer_add(), cli_iran_setup(), create_iran_peer(), install_service(), install_watchdog(), interactive_add_iran_peer() (+8 more)

### Community 5 - "Community 5"
Cohesion: 0.26
Nodes (13): apply_foreign(), apply_foreign_node(), cli_node_add(), confirm_yes(), ipt_add(), node_idx_taken(), setup_foreign(), valid_iface() (+5 more)

### Community 6 - "Community 6"
Cohesion: 0.40
Nodes (10): d_fail(), d_pass(), d_warn(), doctor(), doctor_gre_filtered_hint(), doctor_peer_dnat(), doctor_peer_mss(), doctor_peer_snat() (+2 more)

### Community 7 - "Community 7"
Cohesion: 0.70
Nodes (4): install.sh script, download_release(), progress(), verify_checksum()

### Community 8 - "Community 8"
Cohesion: 0.40
Nodes (5): banner(), create_tunnel(), iran_conf_is_legacy(), load_global_conf(), tun_exists()

### Community 10 - "Community 10"
Cohesion: 0.67
Nodes (3): gre_tunnel_names(), managed_tunnel_names(), unmanaged_gre_tunnels()

## Knowledge Gaps
- **1 isolated node(s):** `gre.bash script`
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ok()` connect `Community 0` to `Community 1`, `Community 2`, `Community 4`, `Community 5`, `Community 6`, `Community 8`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **Why does `info()` connect `Community 0` to `Community 1`, `Community 2`, `Community 4`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.012) - this node is a cross-community bridge._
- **Why does `err()` connect `Community 2` to `Community 0`, `Community 1`, `Community 4`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.007) - this node is a cross-community bridge._
- **What connects `gre.bash script` to the rest of the system?**
  _1 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.10526315789473684 - nodes in this community are weakly interconnected._