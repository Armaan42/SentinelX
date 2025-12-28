-- Add user_id column to track ownership
ALTER TABLE public.scan_history 
ADD COLUMN user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;

-- Drop the overly permissive policies
DROP POLICY IF EXISTS "Allow public read access" ON public.scan_history;
DROP POLICY IF EXISTS "Allow public insert access" ON public.scan_history;
DROP POLICY IF EXISTS "Allow public delete access" ON public.scan_history;

-- Create proper RLS policies for authenticated users only
CREATE POLICY "Users can view their own scans"
ON public.scan_history
FOR SELECT
TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own scans"
ON public.scan_history
FOR INSERT
TO authenticated
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own scans"
ON public.scan_history
FOR DELETE
TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own scans"
ON public.scan_history
FOR UPDATE
TO authenticated
USING (auth.uid() = user_id);