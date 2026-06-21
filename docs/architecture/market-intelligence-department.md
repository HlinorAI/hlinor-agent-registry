# Market Intelligence Department

Market Intelligence is a Hlinor department for structured competitive and category intelligence.

It is not a scraping pipeline by default. It defines safe storage, provenance, freshness, dedupe, and project-isolation rules for future collection workflows.

## Purpose

The department maintains structured knowledge by vertical/category: roofing, HVAC, dentistry, landscaping, pest control, powersports, ecommerce.

It may later support competitor benchmarking, weak-site pattern discovery, CTA analysis, visual pattern tracking, review/reputation analysis, repair-pattern reuse, and category-specific outreach reasoning.

## Boundaries

Market Intelligence must not send outreach, create drafts, write to CRM, write to Zoho, trigger Telegram notifications, modify production queues, reuse data across projects without explicit project binding, or treat old exports as fresh discovery.

## Required controls

Every intelligence record must include project_id, source reference, captured_at timestamp, freshness_at timestamp, provenance note, dedupe key, and confidence level.

## Project isolation

All data must be scoped to a project.

K16 may use Market Intelligence, but Market Intelligence is not K16-specific. Other Hlinor projects may use the same department model only with separate storage, ledgers, reports, and suppression state.

## Freshness

Old data may be used for history, dedupe, and trend analysis. Fresh decision-making requires a current source check before operational action.

## Dedupe

Records should dedupe by normalized domain, normalized business name, phone number when available, and canonical source URL when available.

## Safe default mode

Default mode is documentation and structured data design only. Live collection, crawling, scraping, screenshot capture, model-heavy analysis, CRM writes, email drafting, and outreach require explicit task-level authorization.
