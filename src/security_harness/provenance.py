from __future__ import annotations
import re

def _label(text):
    return re.sub(r"[^\w .:/-]","_",str(text))[:120]

async def build_trace(audit,root: str) -> dict:
    rows = await audit.trace(root)
    nodes,edges,timeline,last = [],[],[],{}
    ids = {row["event_id"]:f"e{i}" for i,row in enumerate(rows)}
    agents = {}
    for i,row in enumerate(rows):
        envelope = row["envelope"]
        agent = row["agent_id"]
        agents.setdefault(agent,f"a{len(agents)}")
        nodes.append({"id":row["event_id"],"agent_id":agent,"event_type":row["event_type"],
            "decision":row["decision"],"status":row["status"],"trace":envelope["trace"],
            "sources":envelope["sources"],"impacts":envelope.get("impacts",[]),"payload_digest":row["payload_digest"]})
        lane = (agent,row["session_id"])
        if lane in last: edges.append({"from":last[lane],"to":row["event_id"],"kind":"sequence"})
        last[lane] = row["event_id"]
        parent = envelope.get("causal_event_id")
        if parent: edges.append({"from":parent,"to":row["event_id"],"kind":"causal"})
        timeline.append({"event_id":row["event_id"],"agent_id":agent,"seq":row["seq"],
                         "occurred_at":envelope["occurred_at"],"received_at":row["received_at"]})
    dag = ["flowchart TD"]
    for node in nodes:
        dag.append(f'  {ids[node["id"]]}["{_label(node["agent_id"])}: {_label(node["event_type"])} / {_label(node["decision"])}"]')
    for edge in edges:
        if edge["from"] in ids: dag.append(f'  {ids[edge["from"]]} -->|{edge["kind"]}| {ids[edge["to"]]}')
    sequence = ["sequenceDiagram"]
    node_by_id = {node["id"]:node for node in nodes}
    parents = {edge["to"]:edge["from"] for edge in edges if edge["kind"]=="causal"}
    for agent,key in agents.items(): sequence.append(f"  participant {key} as {_label(agent)}")
    for node in nodes:
        key = agents[node["agent_id"]]
        parent = node_by_id.get(parents.get(node["id"]))
        source = agents[parent["agent_id"]] if parent else key
        sequence.append(f'  {source}->>{key}: {_label(node["event_type"])} / {_label(node["decision"])}')
    return {"root_session_id":root,"nodes":nodes,"edges":edges,"timeline":timeline,
            "dag_mermaid":"\n".join(dag),"sequence_mermaid":"\n".join(sequence),
            "evidence_mode":"digest","offset_unit":"adapter-supplied original content"}
