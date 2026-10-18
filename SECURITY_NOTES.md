# Security baseline – anonymous access

Date: 2026-10-18

- Anonymous GET /recipes → 200 OK, returns full recipe list (including ingredients, instructions).
- Anonymous DELETE /recipes/1 → 204 No Content, recipe id 1 no longer appears in GET /recipes.
