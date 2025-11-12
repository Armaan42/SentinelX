import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface Top10VulnerabilitiesChartProps {
  data: {
    labels: string[];
    scores: number[];
  };
}

const Top10VulnerabilitiesChart = ({ data }: Top10VulnerabilitiesChartProps) => {
  const chartData = data.labels.map((label, index) => ({
    name: label.length > 30 ? label.substring(0, 28) + '...' : label,
    fullName: label,
    score: data.scores[index]
  })).sort((a, b) => b.score - a.score);

  const getBarColor = (score: number) => {
    if (score >= 80) return '#dc2626'; // Critical
    if (score >= 60) return '#f97316'; // High
    if (score >= 40) return '#eab308'; // Medium
    return '#3b82f6'; // Low
  };

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border border-border rounded-lg p-3 shadow-lg max-w-xs">
          <p className="font-semibold text-sm">{payload[0].payload.fullName}</p>
          <p className="text-sm text-muted-foreground">
            Risk Score: {payload[0].value}
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <ResponsiveContainer width="100%" height={400}>
      <BarChart 
        data={chartData} 
        layout="vertical"
        margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
        <XAxis 
          type="number" 
          domain={[0, 100]}
          tick={{ fill: 'hsl(var(--foreground))' }}
        />
        <YAxis 
          type="category" 
          dataKey="name" 
          width={150}
          tick={{ fill: 'hsl(var(--foreground))', fontSize: 11 }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="score" radius={[0, 4, 4, 0]}>
          {chartData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
};

export default Top10VulnerabilitiesChart;
