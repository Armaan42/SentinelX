import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

interface AttackSurfaceChartProps {
    data: {
        name: string;
        value: number;
        color: string;
    }[];
}

const AttackSurfaceChart = ({ data }: AttackSurfaceChartProps) => {
    const CustomTooltip = ({ active, payload }: any) => {
        if (active && payload && payload.length) {
            return (
                <div className="bg-card border border-border rounded-lg p-3 shadow-lg">
                    <p className="font-semibold text-foreground">{payload[0].name}</p>
                    <p className="text-sm text-muted-foreground">
                        Vectors: <span className="font-bold text-foreground">{payload[0].value}</span>
                        <span className="ml-1 text-xs opacity-70">
                            ({(payload[0].payload.percent * 100).toFixed(0)}%)
                        </span>
                    </p>
                </div>
            );
        }
        return null;
    };

    return (
        <div className="bg-card rounded-lg p-2 h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                    >
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                        ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend verticalAlign="bottom" height={36} iconType="circle" />
                    <text
                        x="50%"
                        y="50%"
                        textAnchor="middle"
                        dominantBaseline="middle"
                        className="fill-foreground font-bold text-xl"
                        style={{ fontSize: '24px', fontWeight: 'bold', fill: 'currentColor' }}
                    >
                        {data.reduce((acc, curr) => acc + curr.value, 0)}
                    </text>
                    <text
                        x="50%"
                        y="50%"
                        dy={20}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        className="fill-muted-foreground text-xs"
                    >
                        Vectors
                    </text>
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
};

export default AttackSurfaceChart;
