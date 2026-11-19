"""ks.world: scenario, agents' behaviour, tools, injector (ADR-06). Owner: tara.

SKEL-01 ships ``skeleton`` (agent behaviour, imported inside agent processes) and ``tools`` (the gateway-side
``ToolDispatcher``). Never imports ks.runtime (B3-37); randomness comes from ks.rng.
"""
