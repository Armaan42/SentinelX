import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface Top10VulnerabilitiesChartProps {
  data: {
    labels: string[];
    scores: number[];
  };
}

const Top10VulnerabilitiesChart = ({ data }: Top10VulnerabilitiesChartProps) => {
  const chartData = data.labels.map((label, index) => ({
    name: label.length > 25 ? label.substring(0, 23) + '...' : label,
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
        <div className="bg-card border border-border rounded-lg p-3 shadow-lg max-w-xs">
          <p className="font-semibold text-sm text-white">{payload[0].payload.fullName}</p>
          <p className="text-sm text-gray-300">
            Risk Score: <span className="font-bold text-white">{payload[0].value}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-card rounded-lg p-4">
      <ResponsiveContainer width="100%" height={400}>
        <BarChart 
          data={chartData} 
          layout="vertical"
          margin={{ top: 5, right: 30, left: 10, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={true} vertical={true} />
          <XAxis 
            type="number" 
            domain={[0, 100]}
            tick={{ fill: '#ffffff', fontSize: 12 }}
            axisLine={{ stroke: '#444' }}
            tickLine={{ stroke: '#444' }}
          />
          <YAxis 
            type="category" 
            dataKey="name" 
            width={180}
            tick={{ fill: '#ffffff', fontSize: 11 }}
            axisLine={{ stroke: '#444' }}
            tickLine={{ stroke: '#444' }}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
          <Bar dataKey="score" radius={[0, 4, 4, 0]}>
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default Top10VulnerabilitiesChart;