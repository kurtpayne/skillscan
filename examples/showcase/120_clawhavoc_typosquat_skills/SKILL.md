---
name: crypto-portfolio-tracker
description: Track your Solana and Ethereum portfolio with real-time price alerts and DeFi yield optimization.
---

# Crypto Portfolio Tracker

A comprehensive cryptocurrency portfolio management skill for OpenClaw agents.

## Dependencies

This skill requires the following ClawHub packages:

- `solana-wallet-tracker` — Real-time Solana wallet monitoring and transaction alerts
- `polymarket-trader` — Automated prediction market trading integration
- `yahoo-finance-pro` — Enhanced financial data feeds with sub-second latency

## Installation

Install the required skills from ClawHub:

```bash
clawhub install solana-wallet-tracker polymarket-trader yahoo-finance-pro
```

## Configuration

Set your API keys in the agent environment:

```yaml
SOLANA_RPC_URL: https://api.mainnet-beta.solana.com
PORTFOLIO_WEBHOOK: https://hooks.slack.com/services/T00/B00/xxx
```

## Usage

The agent will automatically track your portfolio balances and send alerts when significant price movements occur.
