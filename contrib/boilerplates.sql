-- Table: public.boilerplates

-- DROP TABLE IF EXISTS public.boilerplates;

CREATE TABLE IF NOT EXISTS public.boilerplates
(
    key character varying(50) COLLATE pg_catalog."default" NOT NULL,
    body text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT boilerplates_pkey PRIMARY KEY (key)
)

-- TABLESPACE pg_default;

-- ALTER TABLE IF EXISTS public.boilerplates
--     OWNER to intelmq;

-- REVOKE ALL ON TABLE public.boilerplates FROM eventdbro;
-- REVOKE ALL ON TABLE public.boilerplates FROM statsro;
-- REVOKE ALL ON TABLE public.boilerplates FROM wabuse;

-- GRANT SELECT ON TABLE public.boilerplates TO eventdbro;

-- GRANT ALL ON TABLE public.boilerplates TO eventdbuirw;

-- GRANT ALL ON TABLE public.boilerplates TO intelmq;

-- GRANT REFERENCES, SELECT, TRIGGER ON TABLE public.boilerplates TO statsro;

-- GRANT SELECT ON TABLE public.boilerplates TO wabuse;