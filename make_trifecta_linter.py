import json
import re
import argparse

def load_blueprint(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if "flow" not in data:
                print("[-] Error: No 'flow' key found in blueprint.")
                return None
            return data
    except Exception as e:
        print(f"[-] Error loading file: {e}")
        return None

def classify_module(module_name):
    name = module_name.lower()
    if any(x in name for x in ["webhook", "typeform", "google-forms"]): return "UNTRUSTED_INPUT"
    if any(x in name for x in ["openai", "anthropic", "claude", "gemini"]): return "LLM_NODE"
    if any(x in name for x in ["gmail", "email", "slack", "http"]): return "OUTBOUND_EGRESS"
    return "UNKNOWN"

def analyze_blueprint(blueprint, gateway_host=None):
    modules = blueprint["flow"]
    nodes = {}
    
    print("\n[+] SHADOW AGENT SCANNER INITIALIZED")
    print(f"[+] Modules discovered: {len(modules)}")
    
    for mod in modules:
        mod_id = mod.get("id")
        mod_type = mod.get("module", "unknown")
        classification = classify_module(mod_type)
        nodes[mod_id] = {"type": mod_type, "class": classification, "raw": mod}
        print(f"    [{mod_id}] {mod_type:<40} -> {classification}")

    print("\n[*] Initiating Static Mapping-Reference Analysis...")
    trifecta_found = False
    
    input_nodes = [mid for mid, n in nodes.items() if n["class"] == "UNTRUSTED_INPUT"]
    llm_nodes = [mid for mid, n in nodes.items() if n["class"] == "LLM_NODE"]
    egress_nodes = [mid for mid, n in nodes.items() if n["class"] == "OUTBOUND_EGRESS"]

    # Gateway Logic Check
    if gateway_host:
        for mid, n in nodes.items():
            if n["class"] == "LLM_NODE":
                print(f"\n[WARNING] Native LLM module [{mid}] ({n['type']}) detected. Native modules typically bypass corporate AI Gateways.")
            if "http" in n["type"].lower():
                mapper_str = json.dumps(n["raw"].get("mapper", {}))
                if "api.openai.com" in mapper_str or "api.anthropic.com" in mapper_str:
                    print(f"\n[WARNING] HTTP Module [{mid}] calls a direct LLM provider. Ensure it routes through {gateway_host}.")

    if not (input_nodes and llm_nodes and egress_nodes):
        print("[LOW] Missing one or more nodes in the Trifecta. No direct path found.")
        return

    for llm_id in llm_nodes:
        llm_mapper = json.dumps(nodes[llm_id]["raw"].get("mapper", {}))
        for in_id in input_nodes:
            if re.search(r"\{\{\s*" + str(in_id) + r"\.", llm_mapper):
                print(f"\n[!] Data Flow Detected: Input [{in_id}] -> LLM [{llm_id}]")
                
                for eg_id in egress_nodes:
                    eg_mapper = json.dumps(nodes[eg_id]["raw"].get("mapper", {}))
                    if re.search(r"\{\{\s*" + str(eg_id) + r"\.", eg_mapper) or re.search(r"\{\{\s*" + str(llm_id) + r"\.", eg_mapper):
                        print(f"[!] Data Flow Detected: LLM [{llm_id}] -> Egress [{eg_id}]")
                        print("\n[REVIEW REQUIRED] CANDIDATE DATA-FLOW PATH DETECTED")
                        print(f"           Path: Input [{in_id}] -> LLM [{llm_id}] -> Egress [{eg_id}]")
                        print("           Evidence: Variable references found between nodes.")
                        print("           Gateway mediation: NOT ESTABLISHED FROM BLUEPRINT")
                        print("           OAuth Scope: UNVERIFIABLE STATICALLY")
                        print("           Data sensitivity: NOT ASSESSED")
                        print("           Runtime execution: NOT ESTABLISHED")
                        trifecta_found = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Make.com Trifecta Linter")
    parser.add_argument("file", help="Path to Make.com blueprint JSON")
    parser.add_argument("--gateway-host", help="Corporate AI Gateway host to check against", default=None)
    args = parser.parse_args()
    
    blueprint = load_blueprint(args.file)
    if blueprint:
        analyze_blueprint(blueprint, args.gateway_host)