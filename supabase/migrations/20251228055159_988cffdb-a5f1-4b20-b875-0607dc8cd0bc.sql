-- Delete orphaned scan records with NULL user_id
DELETE FROM public.scan_history WHERE user_id IS NULL;

-- Make user_id NOT NULL to prevent RLS bypass
ALTER TABLE public.scan_history 
ALTER COLUMN user_id SET NOT NULL;