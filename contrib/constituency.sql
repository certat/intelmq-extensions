ALTER TABLE events ADD COLUMN IF NOT EXISTS constituency VARCHAR(10);

-- Index: events_constituency_idx

-- DROP INDEX IF EXISTS public.events_constituency_idx;

CREATE INDEX IF NOT EXISTS events_constituency_idx
    ON public.events USING btree
    (constituency COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;