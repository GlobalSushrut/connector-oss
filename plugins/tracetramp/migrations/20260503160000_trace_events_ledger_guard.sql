-- Ledger guard (blockchain-inspired): execution evidence is append-only.
-- DELETE is forbidden. UPDATE may only extend `metadata` (e.g. response_preview backfill); core cells stay immutable.
-- Bypass of enforcement still requires not using this ingress; bypass of *history* requires breaking DB policy or superuser.

CREATE OR REPLACE FUNCTION tracetramp_trace_events_ledger_guard()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'trace_events: DELETE forbidden (append-only ledger)';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.id IS DISTINCT FROM NEW.id
       OR OLD.trace_id IS DISTINCT FROM NEW.trace_id
       OR OLD.request_id IS DISTINCT FROM NEW.request_id
       OR OLD.event_type IS DISTINCT FROM NEW.event_type
       OR OLD.step IS DISTINCT FROM NEW.step
       OR OLD.result IS DISTINCT FROM NEW.result
       OR OLD.created_at IS DISTINCT FROM NEW.created_at
    THEN
      RAISE EXCEPTION 'trace_events: immutable columns cannot change (metadata-only updates allowed)';
    END IF;
    RETURN NEW;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trace_events_ledger_guard ON trace_events;
CREATE TRIGGER trace_events_ledger_guard
  BEFORE UPDATE OR DELETE ON trace_events
  FOR EACH ROW
  EXECUTE PROCEDURE tracetramp_trace_events_ledger_guard();
