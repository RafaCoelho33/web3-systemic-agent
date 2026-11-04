"""
Pydantic schemas and data models for Web3 Condition-Action Trigger Agent.
Defines schemas for deterministic conditions, semantic evaluations, payloads, and results.
"""

from enum import Enum
import re
from typing import Dict, Any, Optional, List, Literal
from pydantic import BaseModel, Field, field_validator
from web3 import Web3


class ChainId(int, Enum):
    BASE_MAINNET = 8453
    BASE_SEPOLIA = 84532
    ARBITRUM_ONE = 42161


class DeterministicCondition(BaseModel):
    target_address: str = Field(..., description="Contract or wallet address to monitor")
    min_value_wei: int = Field(default=0, ge=0, description="Minimum transaction or balance value in Wei")
    required_function_selectors: Optional[List[str]] = Field(
        default=None, description="List of 4-byte hex function selectors (e.g., ['0xa9059cbb'])"
    )
    check_native_balance: bool = Field(default=False, description="Whether to check native ETH balance of target")

    @field_validator("target_address")
    @classmethod
    def validate_checksum_address(cls, v: str) -> str:
        if not Web3.is_address(v):
            raise ValueError(f"Invalid Ethereum address: {v}")
        return Web3.to_checksum_address(v)

    @field_validator("required_function_selectors")
    @classmethod
    def validate_function_selectors(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        selector_regex = re.compile(r"^0x[0-9a-fA-F]{8}$")
        normalized = []
        for selector in v:
            if not isinstance(selector, str) or not selector_regex.match(selector):
                raise ValueError(
                    f"Invalid function selector format '{selector}'. "
                    f"Must be a 10-character hex string starting with '0x' (e.g., '0xa9059cbb')."
                )
            normalized.append(selector.lower())
        return normalized


class SemanticCondition(BaseModel):
    enabled: bool = Field(default=True, description="Whether LLM evaluation is required after deterministic match")
    policy_prompt: str = Field(
        ..., description="Natural language rule to verify against the transaction/proposal context"
    )
    risk_threshold: float = Field(default=7.0, ge=0.0, le=10.0, description="Minimum risk score to flag")


class ConditionRulePayload(BaseModel):
    rule_id: str = Field(..., description="Unique identifier for the monitoring rule")
    chain_id: ChainId = Field(default=ChainId.BASE_SEPOLIA)
    deterministic: DeterministicCondition
    semantic: SemanticCondition
    context_metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Proposal text, calldata, or extra metadata to inspect"
    )


class DeterministicResult(BaseModel):
    passed: bool
    reason: str
    observed_data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class LLMAuditOutput(BaseModel):
    conditions_met: bool = Field(..., description="Whether the semantic policy condition was triggered")
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Calculated risk score from 0.0 to 10.0")
    flagged_issues: List[str] = Field(..., description="Specific technical or governance issues found")
    summary: str = Field(..., description="Concise technical justification of the evaluation")
    recommended_action: Literal["APPROVE", "REJECT", "MANUAL_REVIEW"] = Field(
        ..., description="Actionable recommendation: APPROVE, REJECT, or MANUAL_REVIEW"
    )

    @field_validator("recommended_action", mode="before")
    @classmethod
    def normalize_recommended_action(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip().upper()
        return v


class SemanticAuditResult(BaseModel):
    conditions_met: bool = Field(..., description="Whether the semantic policy condition was triggered")
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Calculated risk score from 0.0 to 10.0")
    flagged_issues: List[str] = Field(default_factory=list, description="Specific technical or governance issues found")
    summary: str = Field(..., description="Concise technical justification of the evaluation")
    recommended_action: Literal["APPROVE", "REJECT", "MANUAL_REVIEW"] = Field(
        ..., description="Actionable recommendation: APPROVE, REJECT, or MANUAL_REVIEW"
    )
    cached: Optional[bool] = Field(default=False, description="Whether this result was served from semantic cache")
    provider: Optional[str] = Field(default=None, description="LLM provider identifier ('gemini', 'openai', or 'mock')")
    model: Optional[str] = Field(default=None, description="Model name used for evaluation")
    input_tokens: int = Field(default=0, ge=0, description="Input prompt token count")
    output_tokens: int = Field(default=0, ge=0, description="Output completion token count")
    estimated_cost_usd: float = Field(default=0.0, ge=0.0, description="Estimated USD cost of LLM call")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Evaluation latency in milliseconds")

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SemanticAuditResult):
            return False
        # Core audit fields must match
        if (
            self.conditions_met != other.conditions_met
            or self.risk_score != other.risk_score
            or self.flagged_issues != other.flagged_issues
            or self.summary != other.summary
            or self.recommended_action != other.recommended_action
            or (self.cached or False) != (other.cached or False)
        ):
            return False
        # Telemetry fields: if specified on both, they must match
        for field in ("provider", "model"):
            v1, v2 = getattr(self, field), getattr(other, field)
            if v1 is not None and v2 is not None and v1 != v2:
                return False
        for field in ("input_tokens", "output_tokens"):
            v1, v2 = getattr(self, field, 0), getattr(other, field, 0)
            if v1 != 0 and v2 != 0 and v1 != v2:
                return False
        if (
            getattr(self, "estimated_cost_usd", 0.0) != 0.0
            and getattr(other, "estimated_cost_usd", 0.0) != 0.0
            and self.estimated_cost_usd != other.estimated_cost_usd
        ):
            return False
        if (
            getattr(self, "latency_ms", 0.0) != 0.0
            and getattr(other, "latency_ms", 0.0) != 0.0
            and self.latency_ms != other.latency_ms
        ):
            return False
        return True

    @field_validator("recommended_action", mode="before")
    @classmethod
    def normalize_recommended_action(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip().upper()
        return v


class PaymentReceipt(BaseModel):
    payment_id: str = Field(..., description="Unique payment identifier or EIP-3009 nonce")
    payer_address: str = Field(..., description="Checksummed EVM address of the paying agent")
    pay_to_address: str = Field(..., description="Checksummed EVM address receiving the payment")
    amount_usdc: float = Field(..., ge=0.0, description="Settled amount in USDC (e.g. 0.01)")
    amount_atomic: int = Field(..., ge=0, description="Settled amount in USDC atomic units (6 decimals, e.g. 10000)")
    network: str = Field(default="eip155:84532", description="CAIP-2 network identifier")
    asset: str = Field(default="USDC", description="Payment token symbol or contract address")
    tx_hash: str = Field(..., description="On-chain settlement transaction hash")
    endpoint: str = Field(..., description="API endpoint paid for")
    settled_at: str = Field(..., description="ISO 8601 UTC timestamp of settlement")

    @field_validator("payer_address", "pay_to_address")
    @classmethod
    def normalize_addresses(cls, v: str) -> str:
        if Web3.is_address(v):
            return Web3.to_checksum_address(v)
        return v


class FinalAgentResponse(BaseModel):
    rule_id: str
    chain_id: int
    deterministic_check: DeterministicResult
    llm_invoked: bool
    semantic_Evaluation: Optional[SemanticAuditResult] = None
    payment: Optional[PaymentReceipt] = Field(
        default=None, description="x402 payment receipt when paid mode is active"
    )

