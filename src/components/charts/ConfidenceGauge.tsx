import { RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis } from 'recharts';

interface ConfidenceGaugeProps {
  confidence: number;
}

const ConfidenceGauge = ({ confidence }: ConfidenceGaugeProps) => {
  const data = [
    {
      name: 'Confidence',
      value: confidence,
      fill: confidence >= 80 ? '#22c55e' : confidence >= 60 ? '#eab308' : '#f97316'
    }
  ];

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={200}>
        <RadialBarChart 
          cx="50%" 
          cy="50%" 
          innerRadius="60%" 
          outerRadius="90%" 
          data={data}
          startAngle={180}
          endAngle={0}
        >
          <PolarAngleAxis
            type="number"
            domain={[0, 100]}
            angleAxisId={0}
            tick={false}
          />
          <RadialBar
            background
            dataKey="value"
            cornerRadius={10}
            fill={data[0].fill}
          />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-center">
        <div className="text-4xl font-bold" style={{ color: data[0].fill }}>
          {confidence}%
        </div>
        <div className="text-sm text-muted-foreground mt-1">Confidence</div>
      </div>
    </div>
  );
};

export default ConfidenceGauge;
