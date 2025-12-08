-- Create scan_history table to store past vulnerability scans
CREATE TABLE public.scan_history (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id TEXT NOT NULL UNIQUE,
  target_url TEXT NOT NULL,
  final_url TEXT NOT NULL,
  platform TEXT DEFAULT 'unknown',
  security_score NUMERIC(5,2) NOT NULL DEFAULT 0,
  confidence_overall INTEGER NOT NULL DEFAULT 0,
  total_findings INTEGER NOT NULL DEFAULT 0,
  critical_count INTEGER NOT NULL DEFAULT 0,
  high_count INTEGER NOT NULL DEFAULT 0,
  medium_count INTEGER NOT NULL DEFAULT 0,
  low_count INTEGER NOT NULL DEFAULT 0,
  info_count INTEGER NOT NULL DEFAULT 0,
  vulnerable_count INTEGER NOT NULL DEFAULT 0,
  immune_count INTEGER NOT NULL DEFAULT 0,
  risk_level TEXT NOT NULL DEFAULT 'unknown',
  scan_result JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create index for faster queries
CREATE INDEX idx_scan_history_created_at ON public.scan_history(created_at DESC);
CREATE INDEX idx_scan_history_target_url ON public.scan_history(target_url);
CREATE INDEX idx_scan_history_security_score ON public.scan_history(security_score);

-- Enable Row Level Security (public access for now as no auth)
ALTER TABLE public.scan_history ENABLE ROW LEVEL SECURITY;

-- Allow public read/write access (no auth required for demo)
CREATE POLICY "Allow public read access" 
ON public.scan_history 
FOR SELECT 
USING (true);

CREATE POLICY "Allow public insert access" 
ON public.scan_history 
FOR INSERT 
WITH CHECK (true);

CREATE POLICY "Allow public delete access" 
ON public.scan_history 
FOR DELETE 
USING (true);