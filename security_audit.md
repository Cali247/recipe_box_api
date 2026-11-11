# Recipe API Security Audit

## 1. Safe password storage

- Table: `users`
- Columns: `id`, `email`, `password_hash`
- Evidence:
  - Example value: `pbkdf2:sha256:1000000$...$...`
- Conclusion: ✅ Passwords stored as PBKDF2-SHA256 hashes, not plaintext.

---

## 2. Authentication checks (identity)

### POST /recipes

- Anonymous:
  - Identity: none
  - Request: POST /recipes
  - Result: 401 "Authentication required"
- Invalid token:
  - Identity: fake JWT
  - Result: 401 "Invalid token"
- Valid token (me@example.com):
  - Identity: normal user
  - Result: 400 "title and ingredients are required" (passed auth, failed validation)

Conclusion: ✅ Token-based authentication enforced on POST /recipes.

---

## 3. Authorization & ownership

### DELETE /recipes/6 – non-owner

- Identity: `my_user@example.com` (non-owner)
- Result: 403 "forbidden: you do not own this recipe"
- Resource check: recipe remained until owner deleted

### DELETE /recipes/6 – owner

- Identity: `me@example.com` (owner)
- Result: 204 No Content
- Follow-up GET /recipes/6: 404 "recipe not found"

Conclusion: ✅ Ownership checks enforced correctly.

---

## 4. Admin moderation

### DELETE /recipes/6 – admin

- Identity: `admin2@example.com` (admin)
- Result: 204 No Content
- Follow-up GET /recipes/6: 404 "recipe not found"

Conclusion: ✅ Admin can moderate/delete user recipes as designed.

---

## 5. Implementation notes

- Authentication middleware/decorator: `...`  <!-- fill in real name,  @token_required -->
- Ownership check: `...`                    <!-- e.g. @owner_required or inline check -->
- Admin check: `...`                        <!-- e.g. @admin_required -->

No previous exploits from earlier lessons still work:
- Anonymous write attempts → 401
- Invalid-token attempts → 401
- Cross-user deletes → 403
- Admin moderation works as expected.