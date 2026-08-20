"""Boto3 middleware that automatically enforces Agent Identity Guard authorization.

Provides a GuardedSession that wraps boto3 clients so every AWS API call
is pre-authorized through the Agent Identity Guard service before execution.

Example:
    ```python
    from agent_identity_guard import AgentIdentityGuard
    from agent_identity_guard.middleware import GuardedSession

    guard = AgentIdentityGuard(
        endpoint='http://localhost:8080',
        api_key='my-api-key',
    )

    session = GuardedSession(
        guard=guard,
        agent_id='invoice-agent',
        fail_mode='closed',
    )
    client = session.client('s3')
    # All calls go through authorization automatically
    client.get_object(Bucket='invoices-prod', Key='123.pdf')
    ```
"""

from __future__ import annotations

import logging
from typing import Any, Literal, Optional

import boto3
import botocore.config
from botocore.exceptions import ClientError

from agent_identity_guard.client import (
    AgentGuardError,
    AgentIdentityGuard,
    Decision,
)

logger = logging.getLogger(__name__)


class AuthorizationDeniedError(ClientError):
    """Raised when the Agent Identity Guard denies a boto3 operation."""

    def __init__(self, decision: Decision, service: str, operation: str, resource: str) -> None:
        self.decision = decision
        error_response = {
            "Error": {
                "Code": "AgentAuthorizationDenied",
                "Message": (
                    f"Agent authorization denied for {service}:{operation} on {resource}. "
                    f"Risk score: {decision.risk_score}. "
                    f"Reasons: {'; '.join(decision.reasons)}"
                ),
            }
        }
        super().__init__(error_response, operation)


class StepUpRequiredError(ClientError):
    """Raised when additional authentication/approval is required."""

    def __init__(self, decision: Decision, service: str, operation: str, resource: str) -> None:
        self.decision = decision
        error_response = {
            "Error": {
                "Code": "AgentStepUpRequired",
                "Message": (
                    f"Step-up authentication required for {service}:{operation} on {resource}. "
                    f"Explanation: {decision.explanation}"
                ),
            }
        }
        super().__init__(error_response, operation)


class _GuardedClientProxy:
    """Proxy around a boto3 client that intercepts API calls for authorization.

    This proxy transparently wraps attribute access and method calls on the
    underlying boto3 client. For recognized API operations, it performs an
    authorization check before forwarding the call.

    Args:
        client: The underlying boto3 client.
        guard: The AgentIdentityGuard instance.
        agent_id: Identifier of the agent making calls.
        service_name: AWS service name (e.g. 's3', 'dynamodb').
        fail_mode: Behavior on guard service failure — 'closed' (deny) or 'open' (allow).
        principal: Optional principal identity for authorization context.
        data_classification: Optional default data classification.
    """

    def __init__(
        self,
        client: Any,
        guard: AgentIdentityGuard,
        agent_id: str,
        service_name: str,
        fail_mode: Literal["open", "closed"] = "closed",
        principal: str = "",
        data_classification: str = "",
    ) -> None:
        self._client = client
        self._guard = guard
        self._agent_id = agent_id
        self._service_name = service_name
        self._fail_mode = fail_mode
        self._principal = principal
        self._data_classification = data_classification

    def __getattr__(self, name: str) -> Any:
        """Intercept attribute access to wrap API method calls."""
        attr = getattr(self._client, name)

        # Only wrap callable API methods (skip meta, exceptions, etc.)
        if not callable(attr) or name.startswith("_"):
            return attr

        def guarded_call(**kwargs: Any) -> Any:
            resource = self._extract_resource(name, kwargs)
            tool = f"{self._service_name}:{self._to_api_action(name)}"

            try:
                decision = self._guard.authorize(
                    agent=self._agent_id,
                    tool=tool,
                    resource=resource,
                    principal=self._principal,
                    data_classification=self._data_classification,
                    context={"operation": name, "service": self._service_name},
                )
            except AgentGuardError as exc:
                logger.warning(
                    "Agent Identity Guard unavailable: %s. Fail mode: %s",
                    exc,
                    self._fail_mode,
                )
                if self._fail_mode == "closed":
                    raise AuthorizationDeniedError(
                        Decision(
                            allowed=False,
                            denied=True,
                            step_up_required=False,
                            risk_score=100,
                            reasons=["Guard service unavailable", str(exc)],
                            explanation="Failing closed due to guard service unavailability.",
                            correlation_id="",
                        ),
                        self._service_name,
                        name,
                        resource,
                    ) from exc
                # fail_mode == 'open' — allow through
                return attr(**kwargs)

            if decision.denied:
                logger.info(
                    "Authorization DENIED for %s on %s: %s",
                    tool,
                    resource,
                    decision.reasons,
                )
                raise AuthorizationDeniedError(decision, self._service_name, name, resource)

            if decision.step_up_required:
                logger.info(
                    "Step-up required for %s on %s: %s",
                    tool,
                    resource,
                    decision.explanation,
                )
                raise StepUpRequiredError(decision, self._service_name, name, resource)

            if not decision.allowed:
                logger.warning(
                    "Authorization not explicitly allowed for %s on %s (risk_score=%d). Denying.",
                    tool,
                    resource,
                    decision.risk_score,
                )
                raise AuthorizationDeniedError(decision, self._service_name, name, resource)

            # Authorized — execute the actual AWS call
            logger.debug(
                "Authorization ALLOWED for %s on %s (risk_score=%d, correlation_id=%s)",
                tool,
                resource,
                decision.risk_score,
                decision.correlation_id,
            )
            return attr(**kwargs)

        return guarded_call

    def _extract_resource(self, operation: str, kwargs: dict[str, Any]) -> str:
        """Best-effort extraction of the target resource ARN from call parameters.

        Attempts to construct a meaningful resource identifier from common
        parameter patterns across AWS services.

        Args:
            operation: The boto3 operation name.
            kwargs: The keyword arguments to the operation.

        Returns:
            A resource string (ARN or constructed identifier).
        """
        # S3 operations
        bucket = kwargs.get("Bucket", "")
        key = kwargs.get("Key", "")
        if bucket and key:
            return f"arn:aws:s3:::{bucket}/{key}"
        if bucket:
            return f"arn:aws:s3:::{bucket}"

        # DynamoDB operations
        table_name = kwargs.get("TableName", "")
        if table_name:
            return f"arn:aws:dynamodb:::table/{table_name}"

        # Lambda operations
        function_name = kwargs.get("FunctionName", "")
        if function_name:
            return f"arn:aws:lambda:::function:{function_name}"

        # SQS operations
        queue_url = kwargs.get("QueueUrl", "")
        if queue_url:
            return queue_url

        # SNS operations
        topic_arn = kwargs.get("TopicArn", "")
        if topic_arn:
            return topic_arn
        target_arn = kwargs.get("TargetArn", "")
        if target_arn:
            return target_arn

        # Secrets Manager
        secret_id = kwargs.get("SecretId", "")
        if secret_id:
            return f"arn:aws:secretsmanager:::secret:{secret_id}"

        # Generic fallback
        return f"{self._service_name}:{operation}"

    @staticmethod
    def _to_api_action(method_name: str) -> str:
        """Convert a boto3 snake_case method name to PascalCase AWS API action.

        Args:
            method_name: The boto3 method name (e.g. 'get_object').

        Returns:
            PascalCase action name (e.g. 'GetObject').
        """
        return "".join(word.capitalize() for word in method_name.split("_"))


class GuardedSession:
    """A boto3-compatible session that enforces Agent Identity Guard authorization.

    Wraps boto3.Session to produce guarded clients that pre-authorize every
    AWS API call through the Agent Identity Guard service.

    Args:
        guard: An initialized AgentIdentityGuard client.
        agent_id: Identifier of the agent making AWS calls.
        fail_mode: Behavior when the guard service is unavailable.
            - 'closed': Deny all requests (secure default).
            - 'open': Allow requests through (availability-first).
        principal: Optional principal identity for authorization context.
        data_classification: Optional default data classification level.
        session: Optional existing boto3.Session to wrap. Creates a new one if not provided.
        **session_kwargs: Additional keyword arguments passed to boto3.Session.

    Example:
        ```python
        session = GuardedSession(
            guard=guard,
            agent_id='invoice-agent',
            fail_mode='closed',
        )
        s3 = session.client('s3')
        s3.get_object(Bucket='my-bucket', Key='data.json')
        ```
    """

    def __init__(
        self,
        guard: AgentIdentityGuard,
        agent_id: str,
        fail_mode: Literal["open", "closed"] = "closed",
        principal: str = "",
        data_classification: str = "",
        session: Optional[boto3.Session] = None,
        **session_kwargs: Any,
    ) -> None:
        self._guard = guard
        self._agent_id = agent_id
        self._fail_mode = fail_mode
        self._principal = principal
        self._data_classification = data_classification
        self._session = session or boto3.Session(**session_kwargs)

    def client(self, service_name: str, **kwargs: Any) -> _GuardedClientProxy:
        """Create a guarded boto3 client for the specified AWS service.

        All API calls on the returned client are pre-authorized through
        the Agent Identity Guard service.

        Args:
            service_name: AWS service name (e.g. 's3', 'dynamodb', 'lambda').
            **kwargs: Additional keyword arguments passed to boto3's client() method.

        Returns:
            A proxy client that enforces authorization on every call.
        """
        underlying_client = self._session.client(service_name, **kwargs)
        return _GuardedClientProxy(
            client=underlying_client,
            guard=self._guard,
            agent_id=self._agent_id,
            service_name=service_name,
            fail_mode=self._fail_mode,
            principal=self._principal,
            data_classification=self._data_classification,
        )

    def resource(self, service_name: str, **kwargs: Any) -> Any:
        """Create a boto3 resource (not guarded — use client() for authorization).

        Note:
            Resource-level guarding is not supported. Use ``client()`` for
            authorization enforcement. This method is provided for compatibility
            but does NOT perform authorization checks.

        Args:
            service_name: AWS service name.
            **kwargs: Additional keyword arguments.

        Returns:
            A standard boto3 resource (unguarded).
        """
        logger.warning(
            "GuardedSession.resource() does not enforce authorization. "
            "Use .client() for guarded access."
        )
        return self._session.resource(service_name, **kwargs)

    @property
    def session(self) -> boto3.Session:
        """Access the underlying boto3 session."""
        return self._session
