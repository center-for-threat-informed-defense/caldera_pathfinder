from pydantic import BaseModel, Field
from typing import List, Optional
import uuid

"""
CVE data model for network report enrichment. 
"""


class CVE(BaseModel):
    id: str
    modified: Optional[str]
    published: Optional[str]
    access: Optional[dict]
    assigner: Optional[str]
    cvss: Optional[float]
    cvss_time: Optional[str]
    cvss_vector: Optional[str]
    cvss3: Optional[float]
    cwe: Optional[str]
    exploitability3: Optional[dict]
    exploitabilityscore: Optional[float]
    exploitabilityscore3: Optional[float]
    impact: Optional[dict]
    impact3: Optional[dict]
    impactscore: Optional[float]
    impactscore3: Optional[float]
    last_modified: Optional[str]
    products: Optional[list] = []
    references: Optional[list] = []
    summary: Optional[str] = []
    vendors: Optional[list] = []
    vulnerable_configuration: Optional[list] = []
    vulnerable_configuration_cpe_2_2: Optional[list] = []
    vulnerable_configuration_stems: Optional[list] = []
    vulnerable_product: Optional[list] = []
    vulnerable_product_stems: Optional[list] = []
    e_os: Optional[dict]
    e_software: Optional[dict]
