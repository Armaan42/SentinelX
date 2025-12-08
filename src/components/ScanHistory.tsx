import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { 
  History, 
  TrendingUp, 
  TrendingDown, 
  Minus,
  Eye,
  Trash2,
  RefreshCw,
  BarChart3,
  Shield
} from "lucide-react";
import { format } from "date-fns";

interface ScanHistoryItem {
  id: string;
  scan_id: string;
  target_url: string;
  final_url: string;
  platform: string;
  security_score: number;
  confidence_overall: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  vulnerable_count: number;
  immune_count: number;
  risk_level: string;
  created_at: string;
}

interface ScanHistoryProps {
  onViewScan?: (scanResult: any) => void;
}

const ScanHistory = ({ onViewScan }: ScanHistoryProps) => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('scan_history')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setHistory(data || []);
    } catch (error) {
      console.error('Error fetching scan history:', error);
      toast.error('Failed to load scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const deleteScan = async (id: string) => {
    try {
      const { error } = await supabase
        .from('scan_history')
        .delete()
        .eq('id', id);

      if (error) throw error;
      
      setHistory(prev => prev.filter(item => item.id !== id));
      toast.success('Scan deleted');
    } catch (error) {
      toast.error('Failed to delete scan');
    }
  };

  const viewScan = async (scanId: string) => {
    try {
      const { data, error } = await supabase
        .from('scan_history')
        .select('scan_result')
        .eq('scan_id', scanId)
        .single();

      if (error) throw error;
      if (data?.scan_result && onViewScan) {
        onViewScan(data.scan_result);
      }
    } catch (error) {
      toast.error('Failed to load scan result');
    }
  };

  const getRiskBadge = (riskLevel: string) => {
    const variants: Record<string, string> = {
      'SECURE': 'bg-green-500 text-white',
      'LOW RISK': 'bg-blue-500 text-white',
      'MEDIUM RISK': 'bg-yellow-500 text-white',
      'HIGH RISK': 'bg-orange-500 text-white',
      'CRITICAL RISK': 'bg-destructive text-destructive-foreground'
    };
    return <Badge className={variants[riskLevel] || 'bg-muted'}>{riskLevel}</Badge>;
  };

  const getTrendIcon = (currentScore: number, index: number) => {
    if (index >= history.length - 1) return <Minus className="w-4 h-4 text-muted-foreground" />;
    
    const previousScore = history[index + 1]?.security_score || 0;
    if (currentScore > previousScore) {
      return <TrendingUp className="w-4 h-4 text-green-500" />;
    } else if (currentScore < previousScore) {
      return <TrendingDown className="w-4 h-4 text-red-500" />;
    }
    return <Minus className="w-4 h-4 text-muted-foreground" />;
  };

  const getAverageScore = () => {
    if (history.length === 0) return 0;
    return (history.reduce((sum, item) => sum + Number(item.security_score), 0) / history.length).toFixed(1);
  };

  const getTotalScans = () => history.length;

  const getMostScannedDomain = () => {
    if (history.length === 0) return 'N/A';
    const domains = history.map(h => {
      try {
        return new URL(h.target_url).hostname;
      } catch {
        return h.target_url;
      }
    });
    const counts: Record<string, number> = {};
    domains.forEach(d => counts[d] = (counts[d] || 0) + 1);
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A';
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <RefreshCw className="w-6 h-6 animate-spin text-primary" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <History className="w-5 h-5" />
              Scan History
            </CardTitle>
            <CardDescription>
              Track security trends over time and compare reports
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={fetchHistory}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {/* Stats Overview */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-muted rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-primary">{getTotalScans()}</div>
            <div className="text-sm text-muted-foreground">Total Scans</div>
          </div>
          <div className="bg-muted rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-primary">{getAverageScore()}</div>
            <div className="text-sm text-muted-foreground">Avg. Score</div>
          </div>
          <div className="bg-muted rounded-lg p-4 text-center">
            <div className="text-lg font-bold text-primary truncate">{getMostScannedDomain()}</div>
            <div className="text-sm text-muted-foreground">Most Scanned</div>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <BarChart3 className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No scan history yet. Run your first scan to start tracking!</p>
          </div>
        ) : (
          <ScrollArea className="h-[400px]">
            <div className="space-y-3">
              {history.map((item, index) => (
                <div
                  key={item.id}
                  className="border rounded-lg p-4 hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Shield className="w-4 h-4 text-primary flex-shrink-0" />
                        <span className="font-mono text-xs text-muted-foreground">{item.scan_id}</span>
                      </div>
                      <div className="font-medium truncate mb-2" title={item.target_url}>
                        {item.target_url}
                      </div>
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        {getRiskBadge(item.risk_level)}
                        <Badge variant="secondary">
                          Score: {Number(item.security_score).toFixed(1)}
                        </Badge>
                        <Badge variant="outline">
                          {item.platform}
                        </Badge>
                        {getTrendIcon(item.security_score, index)}
                      </div>
                      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                        <span className="text-red-600">{item.critical_count} Critical</span>
                        <span className="text-orange-600">{item.high_count} High</span>
                        <span className="text-yellow-600">{item.medium_count} Medium</span>
                        <span className="text-blue-600">{item.low_count} Low</span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-2">
                        {format(new Date(item.created_at), 'MMM d, yyyy h:mm a')}
                      </div>
                    </div>
                    <div className="flex flex-col gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => viewScan(item.scan_id)}
                      >
                        <Eye className="w-4 h-4 mr-1" />
                        View
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        onClick={() => deleteScan(item.id)}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
};

export default ScanHistory;
