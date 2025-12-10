import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Tooltip } from 'recharts';

interface OWASPRadarChartProps {
  data: {
    labels: string[];
    values: number[];
  };
}

const OWASPRadarChart = ({ data }: OWASPRadarChartProps) => {
  const chartData = data.labels.map((label, index) => ({
    category: label.length > 15 ? label.substring(0, 13) + '...' : label,
    fullCategory: label,
    immunity: data.values[index]
  }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-card border border-border rounded-lg p-3 shadow-lg">
          <p className="font-semibold text-white">{payload[0].payload.fullCategory}</p>
          <p className="text-sm text-gray-300">
            Immunity Score: <span className="font-bold text-white">{payload[0].value}%</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-card rounded-lg p-4">
      <ResponsiveContainer width="100%" height={400}>
        <RadarChart data={chartData}>
          <PolarGrid stroke="#444" />
          <PolarAngleAxis 
            dataKey="category" 
            tick={{ fill: '#ffffff', fontSize: 11 }}
          />
          <PolarRadiusAxis 
            angle={90} 
            domain={[0, 100]}
            tick={{ fill: '#999999', fontSize: 10 }}
            axisLine={{ stroke: '#444' }}
          />
          <Radar 
            name="Immunity Score" 
            dataKey="immunity" 
            stroke="#3b82f6"
            fill="#3b82f6"
            fillOpacity={0.5}
            strokeWidth={2}
          />
          <Tooltip content={<CustomTooltip />} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default OWASPRadarChart;