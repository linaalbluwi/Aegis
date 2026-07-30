"""
Base classes for the Chain of Responsibility pattern.
"""
from abc import ABC, abstractmethod
from fastapi import Request, Response
from typing import Optional, Callable


class Handler(ABC):
    """
    Abstract base for all handlers in the chain.
    Each handler decides: block, pass, or modify.
    """

    @abstractmethod
    async def handle(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """Process the request. Return a Response to block, or call_next() to pass."""
        ...


class MiddlewareChain:
    """
    A chain of handlers that process requests in order.
    """

    def __init__(self):
        self._handlers: list[Handler] = []

    def add(self, handler: Handler) -> 'MiddlewareChain':
        """Add a handler to the chain."""
        self._handlers.append(handler)
        return self

    def remove(self, handler_name: str) -> 'MiddlewareChain':
        """Remove a handler by class name."""
        self._handlers = [h for h in self._handlers if h.__class__.__name__ != handler_name]
        return self

    async def execute(self, request: Request, final_handler: Callable) -> Response:
        """
        Execute the chain. Each handler can block or pass.
        If all handlers pass, the final_handler is called.
        """
        async def run_chain(index: int) -> Response:
            if index >= len(self._handlers):
                return await final_handler(request)

            handler = self._handlers[index]

            async def call_next() -> Response:
                return await run_chain(index + 1)

            return await handler.handle(request, call_next)

        return await run_chain(0)

    @property
    def handlers(self) -> list[str]:
        """List registered handler names."""
        return [h.__class__.__name__ for h in self._handlers]
