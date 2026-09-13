/**
 * apps/api/src/rls-isolation.integration.test.ts
 *
 * CLAUDE.md §9 — "Test Realtime subscriptions as an attacker: a permissive
 * policy on `orders` means anyone can subscribe to every order on the
 * platform." This file is that same adversarial test applied to plain
 * `select`, not just Realtime.
 *
 * Every other integration test in this suite connects with whatever role
 * DATABASE_URL grants (locally, that's a superuser) — which BYPASSES RLS
 * entirely. None of them prove customer isolation. This file is the first
 * one that actually binds a session to a specific, non-superuser
 * `authenticated` identity the way Supabase's real PostgREST layer does,
 * and checks the two things that matter:
 *   1. A broad `select` returns only rows the caller is a party to.
 *   2. Fetching another customer's row BY ID returns zero rows, not an
 *      error — RLS must not leak existence via a permission-denied error.
 *
 * Requires a local Postgres with 0001_foundation.sql + 0002_handoff_codes.sql
 * applied. Skips cleanly if DATABASE_URL is not set, same convention as the
 * rest of this suite.
 *
 * Run against a real Supabase project instead of the local/CI stack, this
 * file's fixture rows CANNOT be fully cleaned up afterward: order_events'
 * append-only trigger correctly refuses to delete the fixture events, and
 * ON DELETE RESTRICT then pins the fixture orders (and transitively their
 * zone and auth.users rows) in place. That's the same trigger this whole
 * file exists to trust — expected behaviour, not a bug in the test.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool, Client } from 'pg';

/**
 * Test-only helper: extract the first row of a query result without a
 * non-null assertion.
 */
function firstRow<T>(result: { rows: readonly T[] }, context: string): T {
  const row = result.rows[0];
  if (!row) throw new Error(`Expected at least one row from: ${context}`);
  return row;
}

const DATABASE_URL = process.env['DATABASE_URL'];
const describeIfDb = DATABASE_URL ? describe : describe.skip;

describeIfDb('Row-level security — genuine cross-party isolation', () => {
  let setupPool: Pool;

  let customerAId: string;
  let customerBId: string;
  let facilityAuthId: string;
  let facilityPartnerId: string;
  let orderAId: string;
  let orderBId: string;

  beforeAll(async () => {
    setupPool = new Pool({ connectionString: DATABASE_URL });

    // 0001_foundation.sql's own review note (line ~27) calls this out
    // explicitly: RLS policies alone are not enough — the `authenticated`
    // role also needs table-level SELECT, or Postgres raises "permission
    // denied for table X" before RLS gets a chance to filter anything. A
    // real Supabase project bootstraps this grant automatically; a
    // hand-rolled Postgres (exactly what CI's service container is) does
    // not, so this test makes no assumption about the container and grants
    // it explicitly. Also grant membership so `SET ROLE authenticated`
    // works even if the connecting role isn't a superuser.
    // partners is included too: several policies above subquery into it
    // (e.g. "facility_partner_id in (select id from partners where
    // auth_user_id = auth.uid())"), so authenticated needs SELECT there as
    // well or Postgres denies the whole query before RLS ever filters
    // anything — this is the exact gap 0001_foundation.sql's own review
    // note calls out.
    await setupPool.query(
      `grant select on public.orders, public.order_events, public.handoff_codes, public.partners to authenticated`,
    );
    await setupPool.query(`do $$ begin
      if not exists (
        select 1 from pg_auth_members m
        join pg_roles r1 on r1.oid = m.roleid
        join pg_roles r2 on r2.oid = m.member
        where r1.rolname = 'authenticated' and r2.rolname = current_user
      ) then
        execute format('grant authenticated to %I', current_user);
      end if;
    end $$;`);

    const customerA = await setupPool.query<{ id: string }>(
      `insert into auth.users (id, email) values (gen_random_uuid(), $1) returning id`,
      [`rls-customer-a-${String(Date.now())}@example.com`],
    );
    customerAId = firstRow(customerA, 'insert auth.users (customer A)').id;

    const customerB = await setupPool.query<{ id: string }>(
      `insert into auth.users (id, email) values (gen_random_uuid(), $1) returning id`,
      [`rls-customer-b-${String(Date.now())}@example.com`],
    );
    customerBId = firstRow(customerB, 'insert auth.users (customer B)').id;

    const facilityUser = await setupPool.query<{ id: string }>(
      `insert into auth.users (id, email) values (gen_random_uuid(), $1) returning id`,
      [`rls-facility-${String(Date.now())}@example.com`],
    );
    facilityAuthId = firstRow(facilityUser, 'insert auth.users (facility partner)').id;

    const facilityPartner = await setupPool.query<{ id: string }>(
      `insert into public.partners (auth_user_id, display_name, daily_capacity) values ($1, 'RLS Test Facility', 10) returning id`,
      [facilityAuthId],
    );
    facilityPartnerId = firstRow(facilityPartner, 'insert public.partners').id;

    const zone = await setupPool.query<{ id: string }>(
      `insert into public.zones (name, city, country_code, boundary)
       values ('RLS Test Zone','Lagos','NG', ST_GeogFromText('POLYGON((3.4 6.4,3.6 6.4,3.6 6.6,3.4 6.6,3.4 6.4))'))
       returning id`,
    );
    const zoneId = firstRow(zone, 'insert public.zones').id;

    const orderA = await setupPool.query<{ id: string }>(
      `insert into public.orders (service_id, customer_id, facility_partner_id, zone_id, total_amount)
       values ('laundry', $1, $2, $3, 500000) returning id`,
      [customerAId, facilityPartnerId, zoneId],
    );
    orderAId = firstRow(orderA, 'insert public.orders (A)').id;

    const orderB = await setupPool.query<{ id: string }>(
      `insert into public.orders (service_id, customer_id, zone_id, total_amount)
       values ('laundry', $1, $2, 700000) returning id`,
      [customerBId, zoneId],
    );
    orderBId = firstRow(orderB, 'insert public.orders (B)').id;

    await setupPool.query(
      `insert into public.order_events (order_id, type, actor, actor_id) values ($1, 'order.paid', 'system', 'system')`,
      [orderAId],
    );
    await setupPool.query(
      `insert into public.order_events (order_id, type, actor, actor_id) values ($1, 'order.paid', 'system', 'system')`,
      [orderBId],
    );

    // A code the CUSTOMER is allowed to see (kind: identity), and one only
    // the FACILITY PARTNER is allowed to see (kind: facility) — both on
    // order A, so the narrower handoff_codes shape can be checked too.
    await setupPool.query(
      `insert into public.handoff_codes (order_id, kind, code, entered_by, expires_at)
       values ($1, 'identity', '1234', 'partner_logistics', now() + interval '10 minutes')`,
      [orderAId],
    );
    await setupPool.query(
      `insert into public.handoff_codes (order_id, kind, code, entered_by, expires_at)
       values ($1, 'facility', '5678', 'partner_logistics', now() + interval '10 minutes')`,
      [orderAId],
    );
  });

  afterAll(async () => {
    await setupPool.end();
  });

  /**
   * Opens a brand-new, dedicated connection bound to one identity and
   * never reused — a fresh Client per call, not a pooled one, so no
   * SET ROLE / request.jwt.claims state can leak between assertions.
   *
   * SET ROLE authenticated + request.jwt.claims is exactly how PostgREST
   * (Supabase's real API layer) binds auth.uid() per request. set_config()
   * is used instead of a literal `SET request.jwt.claims = '...'` purely
   * so the claim value is passed as a bound parameter rather than
   * interpolated into SQL text — same effect, no string-building into a
   * query.
   */
  async function asUser(authUserId: string): Promise<Client> {
    const client = new Client({ connectionString: DATABASE_URL });
    await client.connect();
    await client.query('set role authenticated');
    await client.query(`select set_config('request.jwt.claims', $1, false)`, [
      JSON.stringify({ sub: authUserId, role: 'authenticated' }),
    ]);
    return client;
  }

  describe('orders', () => {
    it('customer A sees only their own order in a broad select', async () => {
      const client = await asUser(customerAId);
      try {
        const result = await client.query<{ id: string }>(`select id from public.orders`);
        const ids = result.rows.map((r) => r.id);
        expect(ids).toContain(orderAId);
        expect(ids).not.toContain(orderBId);
      } finally {
        await client.end();
      }
    });

    it('customer A fetching customer B\'s order BY ID gets zero rows, not an error', async () => {
      const client = await asUser(customerAId);
      try {
        const result = await client.query<{ id: string }>(`select id from public.orders where id = $1`, [orderBId]);
        expect(result.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });

    it('customer B sees only their own order in a broad select', async () => {
      const client = await asUser(customerBId);
      try {
        const result = await client.query<{ id: string }>(`select id from public.orders`);
        const ids = result.rows.map((r) => r.id);
        expect(ids).toContain(orderBId);
        expect(ids).not.toContain(orderAId);
      } finally {
        await client.end();
      }
    });

    it('customer B fetching customer A\'s order BY ID gets zero rows, not an error', async () => {
      const client = await asUser(customerBId);
      try {
        const result = await client.query<{ id: string }>(`select id from public.orders where id = $1`, [orderAId]);
        expect(result.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });
  });

  describe('order_events', () => {
    it('customer A sees only events for their own order', async () => {
      const client = await asUser(customerAId);
      try {
        const broad = await client.query<{ order_id: string }>(`select order_id from public.order_events`);
        expect(broad.rows.every((r) => r.order_id === orderAId)).toBe(true);
        expect(broad.rows.length).toBeGreaterThan(0);

        const byId = await client.query(`select 1 from public.order_events where order_id = $1`, [orderBId]);
        expect(byId.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });

    it('customer B sees only events for their own order', async () => {
      const client = await asUser(customerBId);
      try {
        const broad = await client.query<{ order_id: string }>(`select order_id from public.order_events`);
        expect(broad.rows.every((r) => r.order_id === orderBId)).toBe(true);
        expect(broad.rows.length).toBeGreaterThan(0);

        const byId = await client.query(`select 1 from public.order_events where order_id = $1`, [orderAId]);
        expect(byId.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });
  });

  describe('handoff_codes — the narrower shape (kind decides who can read, not just which order)', () => {
    it('customer A sees the identity code but not the facility code, both on their own order', async () => {
      const client = await asUser(customerAId);
      try {
        const identity = await client.query(`select code from public.handoff_codes where order_id = $1 and kind = 'identity'`, [
          orderAId,
        ]);
        expect(identity.rows).toHaveLength(1);

        const facility = await client.query(`select code from public.handoff_codes where order_id = $1 and kind = 'facility'`, [
          orderAId,
        ]);
        expect(facility.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });

    it('the facility partner sees the facility code but not the identity code, on an order they are assigned to', async () => {
      const client = await asUser(facilityAuthId);
      try {
        const facility = await client.query(`select code from public.handoff_codes where order_id = $1 and kind = 'facility'`, [
          orderAId,
        ]);
        expect(facility.rows).toHaveLength(1);

        const identity = await client.query(`select code from public.handoff_codes where order_id = $1 and kind = 'identity'`, [
          orderAId,
        ]);
        expect(identity.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });

    it('customer B, a stranger to order A, sees neither code — by ID, not just in a broad select', async () => {
      const client = await asUser(customerBId);
      try {
        const anyCode = await client.query(`select code from public.handoff_codes where order_id = $1`, [orderAId]);
        expect(anyCode.rows).toHaveLength(0);
      } finally {
        await client.end();
      }
    });
  });
});
