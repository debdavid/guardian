import os
from typing import TypedDict, Literal
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command, interrupt

# 1. Define the Graph State (The shared "notepad" for the AI)
class GuardianState(TypedDict):
    record: dict
    pii_found: list
    triage_score: str
    compliance_status: str
    human_action: str

# 2. Define the Nodes (The steps in the process)
def scan_node(state: GuardianState):
    print("--- [Node: Scanning Data] ---")
    return {"pii_found": ["Australian Medicare Number"]}

def triage_node(state: GuardianState):
    print("--- [Node: Triaging Risk] ---")
    return {"triage_score": "CRITICAL"}

def human_gate_node(state: GuardianState) -> Command[Literal["quarantine_path", "ignore_path"]]:
    """
    This is the core HITL gate. The graph stops here and waits for your command.
    """
    print("--- [Node: WAITING FOR HUMAN AUTHORITY] ---")
    
    # The 'interrupt' function pauses execution and waits for your input
    decision = interrupt({
        "question": "Guardian has flagged a critical breach. How should we proceed?",
        "risk": state["triage_score"]
    })
    
    # Based on the human input, the graph takes a different path
    if decision == "quarantine":
        return Command(goto="quarantine_path", update={"human_action": "quarantine"})
    else:
        return Command(goto="ignore_path", update={"human_action": "ignore"})

def quarantine_node(state: GuardianState):
    print("--- [Node: Executing Containment] ---")
    return {"compliance_status": "ISOLATED"}

def ignore_node(state: GuardianState):
    print("--- [Node: Closing Incident] ---")
    return {"compliance_status": "DISMISSED_BY_HUMAN"}

# 3. Build the Graph
builder = StateGraph(GuardianState)

builder.add_node("scan", scan_node)
builder.add_node("triage", triage_node)
builder.add_node("human_gate", human_gate_node)
builder.add_node("quarantine_path", quarantine_node)
builder.add_node("ignore_path", ignore_node)

# Set the flow
builder.add_edge(START, "scan")
builder.add_edge("scan", "triage")
builder.add_edge("triage", "human_gate")
builder.add_edge("quarantine_path", END)
builder.add_edge("ignore_path", END)

# Compile the graph
guardian_app = builder.compile()
