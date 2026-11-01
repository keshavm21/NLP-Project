"""MITRE CWE Catalog source (P1).

Downloads the official CWE XML catalog from MITRE
(https://cwe.mitre.org/data/xml/cwec_latest.xml.zip).
Extracts CWE IDs, names, descriptions, and parent-child relations
for hierarchical classification and label descriptions (P4).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile
from typing import Any

import requests

from vulntriage.ingest.base import Source
from vulntriage.utils.logging import get_logger

logger = get_logger(__name__)

_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


class CWESource(Source):
    """Downloads and parses the MITRE CWE catalog."""

    name = "cwe"

    def download(self, force: bool = False) -> None:
        out_path = self.raw_dir / "cwec_latest.xml.zip"
        if out_path.exists() and not force:
            logger.info("CWE: already downloaded; skipping")
            return

        logger.info("CWE: downloading %s...", _CWE_URL)
        r = requests.get(_CWE_URL, timeout=120)
        r.raise_for_status()
        out_path.write_bytes(r.content)

        # Extract XML
        with zipfile.ZipFile(out_path) as zf:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    target_file = self.raw_dir / "cwec.xml"
                    target_file.write_bytes(zf.read(name))
                    logger.info("CWE: extracted %s to %s", name, target_file)
                    break
        logger.info("CWE: download and extraction complete")

    def load_catalog(self) -> dict[str, dict[str, Any]]:
        """Parse CWE XML into a mapping: {cwe_id: {name, description, parents, children}}."""
        xml_path = self.raw_dir / "cwec.xml"
        if not xml_path.exists():
            zip_path = self.raw_dir / "cwec_latest.xml.zip"
            if zip_path.exists():
                with zipfile.ZipFile(zip_path) as zf:
                    for name in zf.namelist():
                        if name.endswith(".xml"):
                            xml_path.write_bytes(zf.read(name))
                            break
            if not xml_path.exists():
                logger.warning("CWE: catalog file not found; run `make data` first")
                return {}

        logger.info("CWE: parsing %s...", xml_path)
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Namespace in CWE XML is typically http://cwe.mitre.org/cwe-7
        ns = {"cwe": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        prefix = "cwe:" if ns else ""

        catalog: dict[str, dict[str, Any]] = {}

        # Parse Weaknesses
        weaknesses_xpath = f".//{prefix}Weaknesses/{prefix}Weakness" if ns else ".//Weakness"
        for w in root.findall(weaknesses_xpath, ns):
            w_id = f"CWE-{w.get('ID')}"
            name = w.get("Name", "")
            desc_elem = w.find(f"{prefix}Description", ns)
            desc = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

            parents: list[str] = []
            rel_xpath = (
                f"{prefix}Related_Weaknesses/{prefix}Related_Weakness"
                if ns
                else "Related_Weaknesses/Related_Weakness"
            )
            for rel in w.findall(rel_xpath, ns):
                nature = rel.get("Nature")
                target_id = rel.get("CWE_ID")
                if nature in ("ChildOf", "CanPrecede") and target_id:
                    parents.append(f"CWE-{target_id}")

            catalog[w_id] = {
                "id": w_id,
                "name": name,
                "description": desc,
                "parents": parents,
                "children": [],
            }

        # Populate children inversely
        for w_id, info in catalog.items():
            for p in info["parents"]:
                if p in catalog:
                    catalog[p]["children"].append(w_id)

        logger.info("CWE: loaded %d weaknesses from catalog", len(catalog))
        return catalog
