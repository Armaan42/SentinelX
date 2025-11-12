import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Tooltip } from 'recharts';

interface OWASPRadarChartProps {
  data: {
    labels: string[];
    values: number[];
  };
}

const OWASPRadarChart = ({ data }: OWASPRadarChartProps) => {
  const chartData = data.labels.map((label, index) => ({
    category: label.length > 20 ? label.substring(0, 18) + '...' : label,
    fullCategory: label,
    immunity: data.values[index]
  }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border border-border rounded-lg p-3 shadow-lg">
          <p className="font-semibold">{payload[0].payload.fullCategory}</p>
          <p className="text-sm text-muted-foreground">
            Immunity Score: {payload[0].value}%
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <ResponsiveContainer width="100%" height={400}>
      <RadarChart data={chartData}>
        <PolarGrid stroke="hsl(var(--border))" />
        <PolarAngleAxis 
          dataKey="category" 
          tick={{ fill: 'hsl(var(--foreground))', fontSize: 11 }}
        />
        <PolarRadiusAxis 
          angle={90} 
          domain={[0, 100]}
          tick={{ fill: 'hsl(var(--muted-foreground))' }}
        />
        <Radar 
          name="Immunity Score" 
          dataKey="immunity" 
          stroke="hsl(var(--primary))" 
          fill="hsl(var(--primary))" 
          fillOpacity={0.6} 
        />
        <Tooltip content={<CustomTooltip />} />
      </RadarChart>
    </ResponsiveContainer>
  );
};

export default OWASPRadarChart;
