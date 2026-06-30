"""Engines/sharing/ — MISP Sharing Pipeline engine.

This engine publishes OpenTIDE objects (TVM, DOM, MDR) as MISP events
to configured MISP instances. It follows the CoreTIDE engine pattern
with modules for connection, scope filtering, event management, tagging,
and relation resolution.
"""
