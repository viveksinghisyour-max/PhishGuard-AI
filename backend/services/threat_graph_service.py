from typing import Dict, Any, List, Set
from collections import defaultdict
from backend.models.schemas import (
    GraphNode, 
    GraphLink, 
    ThreatCorrelationGraph,
    InvestigationCase
)
from backend.services.case_store import case_store

class ThreatGraphService:
    """
    Threat Topology & Cross-Case Correlation Graph Engine.
    Maps multi-dimensional relationships between incidents, infrastructure,
    threat actors, payload IOCs, and target mailboxes.
    """

    @classmethod
    def build_global_correlation_graph(cls) -> ThreatCorrelationGraph:
        cases = case_store.list_cases()
        nodes_dict: Dict[str, GraphNode] = {}
        links: List[GraphLink] = []
        
        # Track shared pivot points
        ip_to_cases: Dict[str, List[str]] = defaultdict(list)
        domain_to_cases: Dict[str, List[str]] = defaultdict(list)
        hash_to_cases: Dict[str, List[str]] = defaultdict(list)

        for c in cases:
            # 1. Primary Case Node
            case_val = 22 if c.severity == "critical" else (18 if c.severity == "high" else 14)
            nodes_dict[c.case_id] = GraphNode(
                id=c.case_id,
                label=c.case_id,
                type="case",
                val=case_val,
                severity=c.severity,
                metadata={
                    "case_id": c.case_id,
                    "subject": c.subject,
                    "sender": c.sender,
                    "recipient": c.recipient,
                    "threat_score": c.threat_score,
                    "severity": c.severity,
                    "status": c.status,
                    "assigned_analyst": c.assigned_analyst,
                    "created_at": c.created_at,
                    "summary": c.summary
                }
            )

            # 2. Origin IP Node
            if c.earliest_ip and c.earliest_ip not in ("Unknown", "127.0.0.1"):
                ip_id = f"ip:{c.earliest_ip}"
                ip_to_cases[c.earliest_ip].append(c.case_id)
                
                is_threat_ip = c.threat_score >= 60
                nodes_dict[ip_id] = GraphNode(
                    id=ip_id,
                    label=c.earliest_ip,
                    type="ip",
                    val=14,
                    severity="critical" if is_threat_ip else "medium",
                    metadata={
                        "ip": c.earliest_ip,
                        "country": c.origin_country,
                        "associated_case": c.case_id
                    }
                )
                links.append(GraphLink(
                    source=c.case_id,
                    target=ip_id,
                    relation="ROUTED_THROUGH",
                    label="Origin IP"
                ))

            # 3. Sender Domain Node
            domain = c.sender_domain
            if not domain and "@" in c.sender:
                domain = c.sender.split("@")[-1].strip(">").strip()
            
            if domain:
                dom_id = f"dom:{domain.lower()}"
                domain_to_cases[domain.lower()].append(c.case_id)

                is_malicious_dom = c.threat_score >= 65
                nodes_dict[dom_id] = GraphNode(
                    id=dom_id,
                    label=domain,
                    type="domain",
                    val=12,
                    severity="critical" if is_malicious_dom else "medium",
                    metadata={
                        "domain": domain,
                        "sender": c.sender,
                        "associated_case": c.case_id
                    }
                )
                links.append(GraphLink(
                    source=c.case_id,
                    target=dom_id,
                    relation="SENT_FROM",
                    label="Sender Domain"
                ))

            # 4. Target Mailbox Node
            if c.recipient and "@" in c.recipient:
                target_id = f"target:{c.recipient.lower()}"
                nodes_dict[target_id] = GraphNode(
                    id=target_id,
                    label=c.recipient,
                    type="mailbox",
                    val=10,
                    severity="info",
                    metadata={
                        "recipient": c.recipient,
                        "associated_case": c.case_id
                    }
                )
                links.append(GraphLink(
                    source=c.case_id,
                    target=target_id,
                    relation="TARGETED",
                    label="Target Mailbox"
                ))

            # 5. Payload URLs
            for url in c.extracted_urls:
                if url:
                    url_id = f"url:{hash(url)}"
                    nodes_dict[url_id] = GraphNode(
                        id=url_id,
                        label=url[:28] + "..." if len(url) > 30 else url,
                        type="url",
                        val=8,
                        severity="high",
                        metadata={
                            "url": url,
                            "associated_case": c.case_id
                        }
                    )
                    links.append(GraphLink(
                        source=c.case_id,
                        target=url_id,
                        relation="DELIVERED_PAYLOAD",
                        label="Phishing URL"
                    ))

            # 6. File Hash Node
            if c.sha256_hash and len(c.sha256_hash) >= 16:
                short_hash = c.sha256_hash[:12]
                hash_id = f"hash:{short_hash}"
                hash_to_cases[short_hash].append(c.case_id)
                nodes_dict[hash_id] = GraphNode(
                    id=hash_id,
                    label=f"{short_hash}...",
                    type="hash",
                    val=8,
                    severity="medium",
                    metadata={
                        "sha256": c.sha256_hash,
                        "associated_case": c.case_id
                    }
                )
                links.append(GraphLink(
                    source=c.case_id,
                    target=hash_id,
                    relation="EVIDENCE_HASH",
                    label="Artifact Hash"
                ))

        # Discover and synthesize cross-case campaign correlations
        cross_case_pivots_count = 0
        
        # Cross-case IP pivots
        for ip, linked_cases in ip_to_cases.items():
            if len(linked_cases) > 1:
                ip_id = f"ip:{ip}"
                if ip_id in nodes_dict:
                    nodes_dict[ip_id].val = 20
                    nodes_dict[ip_id].metadata["is_pivot"] = True
                    nodes_dict[ip_id].metadata["pivot_count"] = len(linked_cases)
                    nodes_dict[ip_id].metadata["pivot_type"] = "Shared Origin IP"

                # Interconnect correlated cases
                for i in range(len(linked_cases)):
                    for j in range(i + 1, len(linked_cases)):
                        c1, c2 = linked_cases[i], linked_cases[j]
                        links.append(GraphLink(
                            source=c1,
                            target=c2,
                            relation="SHARED_INFRASTRUCTURE",
                            is_cross_case=True,
                            label=f"Co-Located: IP {ip}"
                        ))
                        cross_case_pivots_count += 1

        # Cross-case Domain pivots
        for dom, linked_cases in domain_to_cases.items():
            if len(linked_cases) > 1:
                dom_id = f"dom:{dom}"
                if dom_id in nodes_dict:
                    nodes_dict[dom_id].val = 18
                    nodes_dict[dom_id].metadata["is_pivot"] = True
                    nodes_dict[dom_id].metadata["pivot_count"] = len(linked_cases)
                    nodes_dict[dom_id].metadata["pivot_type"] = "Shared Campaign Domain"

        summary = {
            "total_nodes": len(nodes_dict),
            "total_links": len(links),
            "total_cases": len(cases),
            "cross_case_pivots": cross_case_pivots_count,
            "campaign_clusters": len([ip for ip, c_list in ip_to_cases.items() if len(c_list) > 1])
        }

        return ThreatCorrelationGraph(
            nodes=list(nodes_dict.values()),
            links=links,
            summary=summary
        )

    @classmethod
    def build_case_subgraph(cls, case_id: str) -> ThreatCorrelationGraph:
        """
        Extracts localized 2-hop threat correlation neighborhood for a specific case.
        """
        full_graph = cls.build_global_correlation_graph()
        case_node = next((n for n in full_graph.nodes if n.id == case_id), None)
        if not case_node:
            return ThreatCorrelationGraph(nodes=[], links=[], summary={})

        # 1-hop: directly connected neighbors
        neighbor_ids: Set[str] = {case_id}
        case_links: List[GraphLink] = []

        for link in full_graph.links:
            if link.source == case_id:
                neighbor_ids.add(link.target)
                case_links.append(link)
            elif link.target == case_id:
                neighbor_ids.add(link.source)
                case_links.append(link)

        # 2-hop: secondary cases connected through shared infrastructure
        for link in full_graph.links:
            if link.is_cross_case and (link.source == case_id or link.target == case_id):
                neighbor_ids.add(link.source)
                neighbor_ids.add(link.target)
                if link not in case_links:
                    case_links.append(link)

        sub_nodes = [n for n in full_graph.nodes if n.id in neighbor_ids]

        return ThreatCorrelationGraph(
            nodes=sub_nodes,
            links=case_links,
            summary={
                "focus_case": case_id,
                "total_nodes": len(sub_nodes),
                "total_links": len(case_links),
                "is_subgraph": True
            }
        )

# Global singleton
threat_graph_service = ThreatGraphService()
