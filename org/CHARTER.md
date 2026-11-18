# Project Kill Switch — Team Charter

## Mission
SEED Hackathon 2026, Sub-theme 03 "The Kill Switch" (Agent Safety). Build the black box and the off switch
for a network of autonomous agents.

Official brief (all of it that is public):
- Framing: "Ten agents are working. One just broke something." What changed, who changed it, how fast can it be undone?
- Build an accountability layer: per-agent identity on every action, live monitoring, containment,
  and rollback that reverses one agent's damage WITHOUT discarding the other agents' work.
- Teams win on: time-to-identify, time-to-contain, clean recovery.
- Jury "rewards the team that frames the problem best, not the one that builds the most".
- Judged on real-world impact, not slide decks. Juries will try to break what you built.
  Winners must show an agent that can be audited, not only demoed.

## Constraints
- Abstract: < 1,000 words, problem → fix → why it matters. MUST be written by Aarav himself; organisers check for
  AI-written text. The team NEVER produces submission-ready abstract prose. We produce: framing options, an outline
  of points, facts and numbers with sources, and reviews of Aarav's draft.
- Dates: abstract 22 Nov 2026; shortlist 24 Nov; prototyping 25 Nov–2 Dec (cloud credits); mentorship 3–7 Dec; finale 9 Dec.
- Team size 2–3 humans (Aarav's team). Virtual.
- Product Owner: Aarav — Software Engineer at Barclays (Java, Spring Boot, microservices, OpenTelemetry, GitLab CI),
  moving toward AI/ML engineering. The prototype may use Python for speed, but design choices that map onto
  enterprise reality (OpenTelemetry, policy-as-code, audit for regulated banking) are a strength.

## Working agreement
- Every unit of work is an issue in `org/issues/` created through `python3 org/issue.py`. Small, precise, one outcome,
  testable acceptance criteria.
- Owner moves issue: todo → in_progress → in_review (with `summary`). Reviewer: `review --verdict done|changes`.
- Deliverables go where the issue says (`research/`, `org/adr/`, `src/`, `tests/`, `abstract/`).
- Research must cite sources with URLs. Distinguish fact vs. our opinion. No invented citations/numbers.
- Code: Python 3.13, stdlib + pydantic/cryptography/networkx/pytest where useful; must run offline with no API keys.
- Never touch `board/` or `org/board.json` directly — the coordinator renders the board.
