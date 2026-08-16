-- Reversing this precisely (only the rows this migration itself inserted,
-- not any schedule a user has since customized) isn't safely possible from
-- data alone — a down migration here would risk deleting a schedule a user
-- legitimately edited after the backfill ran. This is a data backfill, not
-- a schema change; there is nothing to structurally revert.
SELECT 1;
