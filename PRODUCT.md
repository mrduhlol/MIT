# AI vs AI — Autonomous Cyber Defense Challenge
<!-- impeccable:product-schema 1 -->
## Platform
web
## Stack
React, TypeScript, Tailwind CSS, Python FastAPI, SQLite. Local prototype.
## Users
Website administrators supervising the AI security agent for their own website and server; challenge evaluators can review its simulated workflow.
## Product Purpose
Provide an advanced website security agent dashboard with scheduled patrols, telemetry charts, searchable logs, correlated incidents, evidence-backed investigation and individually approved defensive responses.
## Operating Context
User clarified that this is the AI agent dashboard inside their own website management experience, and requested advanced graphs and logs. The agent overview leads; incident investigation and individual approval remain central. Patrols run in the backend independently of an open browser.
## Capabilities and Constraints
Supports enrolled Linux collectors and explicitly labeled simulated agents. Real collectors report read-only CPU/memory/uptime and opt-in security logs over verified HTTPS. Admin access remains single-operator and loopback-bootstrapped; no SSH credentials or command channel. Do not mix or fabricate provenance. Websites are associated display labels; no remote probing or arbitrary URL fetching. No real attacks or containment. Every sandbox action requires explicit approval. Report measured synthetic evaluation metrics and model limitations. Official sandbox API is unspecified; local simulation is required until documented integration exists.
## Brand Commitments
Professional dark-mode SOC dashboard. Product name: AI vs AI.
## Product Principles
Evidence before action. Human control over containment. Honest measurements. End-to-end functionality over breadth.
