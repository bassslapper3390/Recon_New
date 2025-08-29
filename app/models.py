from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

class ScanRequest(BaseModel):
	request_id: str
	domain: Optional[str] = Field(default=None)
	ip: Optional[str] = Field(default=None)

class ToolResult(BaseModel):
	name: str
	success: bool
	output: Optional[str] = None
	error: Optional[str] = None

class PassiveResults(BaseModel):
	dns: Optional[Dict[str, Any]] = None
	whois: Optional[Dict[str, Any]] = None
	ssl: Optional[Dict[str, Any]] = None
	http: Optional[Dict[str, Any]] = None
	robots: Optional[str] = None
	ct_logs: Optional[List[Dict[str, Any]]] = None

class ScanResults(BaseModel):
	request: ScanRequest
	passive: PassiveResults
	tools: List[ToolResult] = []
	report_path: Optional[str] = None
	summary: Optional[str] = None
