# Merges Cachi2 reported components into a RHTAP/Syft SBOM
import json
from urllib.parse import urlsplit, quote_plus

with open("gomod-pandemonium/cachi2.bom.json") as file:
    cachi2_sbom = json.load(file)

with open("gomod-pandemonium/rhtap.bom.json") as file:
    rhtap_sbom = json.load(file)

# we want to remove locally replaced Golang modules
# since they'll be reported differently by Cachi2
def is_local_golang_module(component: dict) -> bool:
    return (
        component.get("purl", "").startswith("pkg:golang") and
        component.get("name", "").startswith(".")
    )


def unique_key_cachi2(component: dict) -> str:
    url = urlsplit(component["purl"])
    # omit the query part, since Cachi2 sets it and Syft does not
    return url.scheme + url.path


def unique_key_rhtap(component: dict) -> str:
    # very few components don't have a purl, such as type OS
    if "purl" in component.keys():
        parts = component["purl"].split("@")
        # Syft does not encode special characters in the version
        return parts[0] + quote_plus(parts[1])

    return component.get('name', '') + '@' + component.get('version', '')


filtered_rhtap_components = [
    component for component in rhtap_sbom["components"]
    if not is_local_golang_module(component)
]

indexed_components = {
    unique_key_cachi2(component): component
    for component in cachi2_sbom["components"]
}

# add a property to differentiate Cachi2 reported components from Syft's
for component in indexed_components.values():
    component["properties"] = [{"name": "cachi2:foundBy", "value": "cachi2"}]

# adds non-duplicate RHTAP components into Cachi2's component list
for component in filtered_rhtap_components:
    key = unique_key_rhtap(component)
    if key not in indexed_components.keys():
        indexed_components[key] = component

rhtap_sbom["components"] = list(indexed_components.values())

with open("merged.bom.json", "w") as file:
    json.dump(rhtap_sbom, file)
