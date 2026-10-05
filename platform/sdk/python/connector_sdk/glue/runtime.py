"""
Runtime execution layer for GLUE operations
"""

from typing import Any, Dict, Optional, TYPE_CHECKING
import uuid
import time
import requests

if TYPE_CHECKING:
    from .core import Glue

from .result import GlueResult, GlueReceipt, ResultIntent, ResourceInfo
from .error import GlueError, ErrorCode


def _generate_trace_id() -> str:
    return uuid.uuid4().hex


def _make_receipt(trace_id: str) -> GlueReceipt:
    return GlueReceipt(
        id=f"rcpt_{trace_id[:8]}",
        trace_id=trace_id,
        timestamp_ms=int(time.time() * 1000)
    )


def _api_call(glue: "Glue", method: str, endpoint: str, 
              data: Optional[Dict] = None) -> Dict[str, Any]:
    """Make an API call to the Connector server"""
    url = f"{glue.config.base_url}/api/v1{endpoint}"
    headers = {"Content-Type": "application/json"}
    if glue.config.api_key:
        headers["Authorization"] = f"Bearer {glue.config.api_key}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=data, timeout=30)
        else:
            response = requests.post(url, headers=headers, json=data, timeout=30)
        
        # Check HTTP status
        if response.status_code == 401:
            raise GlueError(
                ErrorCode.AUTH_REQUIRED,
                "Authentication required",
                detail=f"API key missing or invalid for {url}",
                hints=["Set CONNECTOR_API_KEY environment variable", "Check API key validity"]
            )
        elif response.status_code == 403:
            raise GlueError(
                ErrorCode.ACCESS_DENIED,
                "Access denied",
                detail=f"Insufficient permissions for {endpoint}"
            )
        elif response.status_code == 404:
            raise GlueError(
                ErrorCode.NOT_FOUND,
                "Resource not found",
                detail=f"Endpoint {endpoint} not found"
            )
        elif response.status_code == 429:
            raise GlueError(
                ErrorCode.QUOTA_REACHED,
                "Rate limit exceeded",
                detail="Too many requests"
            )
        elif response.status_code >= 500:
            raise GlueError(
                ErrorCode.UNAVAILABLE,
                "Server error",
                detail=f"Server returned {response.status_code}"
            )
        elif response.status_code >= 400:
            raise GlueError(
                ErrorCode.INTERNAL_ERROR,
                f"Request failed with status {response.status_code}",
                detail=response.text[:200] if response.text else None
            )
        
        # Parse response
        try:
            result = response.json()
        except ValueError:
            raise GlueError(
                ErrorCode.INTERNAL_ERROR,
                "Invalid JSON response from server",
                detail=response.text[:200] if response.text else None
            )
        
        # Check for application-level errors
        if isinstance(result, dict) and result.get("ok") is False:
            return result  # Let caller handle application errors
        
        return result
        
    except requests.ConnectionError as e:
        raise GlueError(
            ErrorCode.UNAVAILABLE,
            f"Cannot connect to Connector at {glue.config.base_url}",
            detail=str(e),
            hints=[
                "Check if Connector node is running",
                f"Verify base_url: {glue.config.base_url}",
                "Check network connectivity"
            ]
        )
    except requests.Timeout:
        raise GlueError(
            ErrorCode.TIMEOUT,
            "Request timed out after 30 seconds",
            hints=["Check server health", "Increase timeout if needed"]
        )
    except requests.RequestException as e:
        raise GlueError(
            ErrorCode.UNAVAILABLE,
            "Network request failed",
            detail=str(e)
        )


# =============================================================================
# Core Verb Implementations
# =============================================================================

def execute_run(glue: "Glue", target: str, inputs: Dict[str, Any],
                policy: Optional[str]) -> GlueResult:
    trace_id = _generate_trace_id()
    
    # Try API call
    response = _api_call(glue, "POST", f"/agents/{target}/run", {
        "inputs": inputs,
        "policy": policy
    })
    
    if response.get("ok"):
        result = GlueResult.from_dict(response)
    else:
        # Create local result
        result = GlueResult.success("run", "contract", target)
        result.resource = ResourceInfo(
            id=target,
            uid=f"exec_{trace_id[:12]}",
            kind="execution",
            state="completed"
        )
        result.data = {"inputs": inputs}
        if policy:
            result.data["policy"] = policy
    
    result.receipt = _make_receipt(trace_id)
    return result


def execute_remember(glue: "Glue", key: str, content: str,
                     namespace: Optional[str]) -> GlueResult:
    trace_id = _generate_trace_id()
    ns = namespace or glue.config.default_namespace
    
    _api_call(glue, "POST", "/memory/write", {
        "key": key,
        "content": content,
        "namespace": ns
    })
    
    result = GlueResult.success("remember", "memory", key)
    result.resource = ResourceInfo(
        id=key,
        uid=f"mem_{trace_id[:12]}",
        kind="memory"
    )
    result.data = {"namespace": ns, "content_length": len(content)}
    result.receipt = _make_receipt(trace_id)
    return result


def execute_recall(glue: "Glue", query: str, namespace: Optional[str],
                   limit: int) -> GlueResult:
    trace_id = _generate_trace_id()
    ns = namespace or glue.config.default_namespace
    
    response = _api_call(glue, "GET", "/memory/recall", {
        "query": query,
        "namespace": ns,
        "limit": limit
    })
    
    result = GlueResult.success("recall", "memory", query)
    result.data = {
        "namespace": ns,
        "limit": limit,
        "results": response.get("data", {}).get("results", [])
    }
    result.receipt = _make_receipt(trace_id)
    return result


def execute_search(glue: "Glue", query: str, namespace: Optional[str],
                   limit: int) -> GlueResult:
    trace_id = _generate_trace_id()
    ns = namespace or glue.config.default_namespace
    
    response = _api_call(glue, "POST", "/memory/search", {
        "query": query,
        "namespace": ns,
        "limit": limit
    })
    
    result = GlueResult.success("search", "knowledge", query)
    result.data = {
        "namespace": ns,
        "limit": limit,
        "results": response.get("data", {}).get("results", [])
    }
    result.receipt = _make_receipt(trace_id)
    return result


def execute_show(glue: "Glue", noun: str, target: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/{noun}s/{target}", {})
    
    result = GlueResult.success("show", noun, target)
    result.resource = ResourceInfo(
        id=target,
        uid=response.get("data", {}).get("uid", f"{noun}_{trace_id[:12]}"),
        kind=noun,
        state=response.get("data", {}).get("state")
    )
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_list(glue: "Glue", noun: str, namespace: Optional[str],
                 limit: int) -> GlueResult:
    trace_id = _generate_trace_id()
    
    params = {"limit": limit}
    if namespace:
        params["namespace"] = namespace
    
    response = _api_call(glue, "GET", f"/{noun}s", params)
    
    result = GlueResult.success("list", noun, "all")
    result.data = {
        "items": response.get("data", {}).get("items", []),
        "total": response.get("data", {}).get("total", 0),
        "limit": limit
    }
    if namespace:
        result.data["namespace"] = namespace
    result.receipt = _make_receipt(trace_id)
    return result


def execute_audit(glue: "Glue", target: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/audit/{target}", {})
    
    result = GlueResult.success("audit", "execution", target)
    result.data = {
        "trace": response.get("data", {}).get("trace", []),
        "decisions": response.get("data", {}).get("decisions", [])
    }
    result.receipt = _make_receipt(trace_id)
    return result


def execute_verify(glue: "Glue", what: str, for_agent: Optional[str]) -> GlueResult:
    trace_id = _generate_trace_id()
    
    data = {"policy": what}
    if for_agent:
        data["agent"] = for_agent
    
    response = _api_call(glue, "POST", "/compliance/verify", data)
    
    result = GlueResult.success("verify", "compliance", what)
    result.data = {
        "compliant": response.get("data", {}).get("compliant", True)
    }
    if for_agent:
        result.data["agent"] = for_agent
    result.receipt = _make_receipt(trace_id)
    return result


# =============================================================================
# Agent Operations
# =============================================================================

def agent_start(glue: "Glue", name: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    _api_call(glue, "POST", f"/agents/{name}/start", {})
    
    result = GlueResult.success("start", "agent", name)
    result.resource = ResourceInfo(
        id=name,
        uid=f"agt_{trace_id[:12]}",
        kind="agent",
        state="running"
    )
    result.receipt = _make_receipt(trace_id)
    return result


def agent_stop(glue: "Glue", name: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    _api_call(glue, "POST", f"/agents/{name}/stop", {})
    
    result = GlueResult.success("stop", "agent", name)
    result.resource = ResourceInfo(
        id=name,
        uid=f"agt_{trace_id[:12]}",
        kind="agent",
        state="stopped"
    )
    result.receipt = _make_receipt(trace_id)
    return result


def agent_status(glue: "Glue", name: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/agents/{name}/status", {})
    
    result = GlueResult.success("status", "agent", name)
    result.resource = ResourceInfo(
        id=name,
        uid=response.get("data", {}).get("uid", f"agt_{trace_id[:12]}"),
        kind="agent",
        state=response.get("data", {}).get("state", "unknown")
    )
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def agent_pause(glue: "Glue", name: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    _api_call(glue, "POST", f"/agents/{name}/pause", {})
    
    result = GlueResult.success("pause", "agent", name)
    result.resource = ResourceInfo(
        id=name,
        uid=f"agt_{trace_id[:12]}",
        kind="agent",
        state="paused"
    )
    result.receipt = _make_receipt(trace_id)
    return result


def agent_resume(glue: "Glue", name: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    _api_call(glue, "POST", f"/agents/{name}/resume", {})
    
    result = GlueResult.success("resume", "agent", name)
    result.resource = ResourceInfo(
        id=name,
        uid=f"agt_{trace_id[:12]}",
        kind="agent",
        state="running"
    )
    result.receipt = _make_receipt(trace_id)
    return result


# =============================================================================
# Memory Operations
# =============================================================================

def memory_write(glue: "Glue", namespace: str, content: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    _api_call(glue, "POST", "/memory/write", {
        "namespace": namespace,
        "content": content
    })
    
    result = GlueResult.success("write", "memory", namespace)
    result.data = {"bytes_written": len(content)}
    result.receipt = _make_receipt(trace_id)
    return result


def memory_read(glue: "Glue", namespace: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/memory/{namespace}", {})
    
    result = GlueResult.success("read", "memory", namespace)
    result.data = {"content": response.get("data", {}).get("content")}
    result.receipt = _make_receipt(trace_id)
    return result


def memory_range(glue: "Glue", namespace: str, start: int, end: int) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/memory/{namespace}/range", {
        "start": start,
        "end": end
    })
    
    result = GlueResult.success("range", "memory", namespace)
    result.data = {
        "start": start,
        "end": end,
        "items": response.get("data", {}).get("items", [])
    }
    result.receipt = _make_receipt(trace_id)
    return result


# =============================================================================
# Tool Operations
# =============================================================================

def tool_call(glue: "Glue", name: str, params: Dict[str, Any]) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "POST", f"/tools/{name}/call", {
        "params": params
    })
    
    result = GlueResult.success("call", "tool", name)
    result.data = {
        "params": params,
        "output": response.get("data", {}).get("output")
    }
    result.receipt = _make_receipt(trace_id)
    return result


def tool_info(glue: "Glue", name: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/tools/{name}", {})
    
    result = GlueResult.success("info", "tool", name)
    result.data = response.get("data", {"name": name, "available": True})
    result.receipt = _make_receipt(trace_id)
    return result


# =============================================================================
# Policy Operations
# =============================================================================

def policy_bind(glue: "Glue", policy: str, agent: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    _api_call(glue, "POST", f"/policies/{policy}/bind", {
        "agent": agent
    })
    
    result = GlueResult.success("bind", "policy", policy)
    result.data = {"agent": agent, "bound": True}
    result.receipt = _make_receipt(trace_id)
    return result


def policy_check(glue: "Glue", policy: str, agent: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "POST", f"/policies/{policy}/check", {
        "agent": agent
    })
    
    result = GlueResult.success("check", "policy", policy)
    result.data = {
        "agent": agent,
        "compliant": response.get("data", {}).get("compliant", True)
    }
    result.receipt = _make_receipt(trace_id)
    return result


# =============================================================================
# Infra Operations
# =============================================================================

def execute_explain(glue: "Glue", target: str, last: Optional[str]) -> GlueResult:
    trace_id = _generate_trace_id()
    
    params = {}
    if last:
        params["last"] = last
    
    response = _api_call(glue, "GET", f"/agents/{target}/explain", params)
    
    result = GlueResult.success("explain", "agent", target)
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_prove(glue: "Glue", target: str, forensic: bool) -> GlueResult:
    trace_id = _generate_trace_id()
    
    params = {"forensic": forensic} if forensic else {}
    response = _api_call(glue, "GET", f"/agents/{target}/prove", params)
    
    result = GlueResult.success("prove", "agent", target)
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_trace(glue: "Glue", target: str, last: Optional[str], limit: int) -> GlueResult:
    trace_id = _generate_trace_id()
    
    params = {"limit": limit}
    if last:
        params["last"] = last
    
    response = _api_call(glue, "GET", f"/agents/{target}/trace", params)
    
    result = GlueResult.success("trace", "agent", target)
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_review(glue: "Glue", target: str) -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", f"/agents/{target}/review", {})
    
    result = GlueResult.success("review", "agent", target)
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_cost(glue: "Glue", target: Optional[str], breakdown: bool) -> GlueResult:
    trace_id = _generate_trace_id()
    
    if target:
        endpoint = f"/agents/{target}/cost"
    else:
        endpoint = "/monitor/cost-dashboard"
    
    params = {"breakdown": breakdown} if breakdown else {}
    response = _api_call(glue, "GET", endpoint, params)
    
    result = GlueResult.success("cost", "agent" if target else "node", target or "global")
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_health(glue: "Glue") -> GlueResult:
    trace_id = _generate_trace_id()
    
    response = _api_call(glue, "GET", "/monitor/health", {})
    
    result = GlueResult.success("health", "node", "local")
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_doctor(glue: "Glue", verbose: bool) -> GlueResult:
    trace_id = _generate_trace_id()
    
    params = {"verbose": verbose} if verbose else {}
    response = _api_call(glue, "GET", "/monitor/doctor", params)
    
    result = GlueResult.success("doctor", "node", "local")
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result


def execute_logs(glue: "Glue", target: Optional[str], tail: int) -> GlueResult:
    trace_id = _generate_trace_id()
    
    if target:
        endpoint = f"/agents/{target}/logs"
    else:
        endpoint = "/monitor/logs"
    
    params = {"tail": tail}
    response = _api_call(glue, "GET", endpoint, params)
    
    result = GlueResult.success("logs", "agent" if target else "node", target or "local")
    result.data = response.get("data", {})
    result.receipt = _make_receipt(trace_id)
    return result
