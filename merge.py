# Merges Cachi2 reported components into a RHTAP/Syft SBOM
import json

with open("cachi2.bom.json") as file:
    cachi2_sbom = json.load(file)

with open("rhtap.bom.json") as file:
    rhtap_sbom = json.load(file)

# we want to remove local Golang modules since they'll
# be reported differently by Cachi2
def is_local_golang_module(component: dict) -> bool:
    return (
        component.get("purl", "").startswith("pkg:golang") and
        component.get("name", "").startswith(".")
    )


def unique_key(component: dict) -> str:
    if component.get("purl", ""):
        return component.get("purl")

    return component.get('name', '') + '@' + component.get('version', '')


filtered_rhtap_components = [
    component for component in rhtap_sbom["components"]
    if not is_local_golang_module(component)
]

indexed_components = {
    unique_key(component): component
    for component in cachi2_sbom["components"]
}

# add a property to differentiate Cachi2 reported components from Syft's
for component in indexed_components.values():
    component["properties"] = [{"name": "cachi2:foundBy", "value": "cachi2"}]

# adds non-duplicate RHTAP components into Cachi2's component list
for component in filtered_rhtap_components:
    key = unique_key(component) 
    if key not in indexed_components.keys():
        indexed_components[key] = component

rhtap_sbom["components"] = list(indexed_components.values())

with open("merged.bom.json", "w") as file:
    json.dump(rhtap_sbom, file)
