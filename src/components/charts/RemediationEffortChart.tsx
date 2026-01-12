import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface RemediationEffortChartProps {
    data: {
        severity: string;
        hours: number;
        count: number;
    }[];
}

const COLORS = {
    Critical: '#dc2626',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#3b82f6',
    Info: '#94a3b8'
};

const RemediationEffortChart = ({ data }: RemediationEffortChartProps) => {
    const CustomTooltip = ({ active, payload, label }: any) => {
        if (active && payload && payload.length) {
            return (
                <div className="bg-card border border-border rounded-lg p-3 shadow-lg">
                    <p className="font-semibold text-foreground mb-1">{label}</p>
                    <p className="text-sm text-muted-foreground">
                        Est. Effort: <span className="font-bold text-foreground">{payload[0].value} hours</span>
                    </p>
                    <p className="text-xs text-muted-foreground">
                        {payload[0].payload.count} issues
                    </p>
                </div>
            );
        }
        return null;
    };

    return (
        <div className="bg-card rounded-lg p-2 h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart
                    data={data}
                    layout="vertical"
                    margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
                >
                    <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} stroke="#333" opacity={0.2} />
                    <XAxis type="number" stroke="#888" fontSize={12} unit="h" />
                    <YAxis
                        dataKey="severity"
                        type="category"
                        stroke="#888"
                        fontSize={12}
                        width={60}
                    />
                    <Tooltip content={<CustomTooltip />} cursor={{ fill: 'transparent' }} />
                    <Bar dataKey="hours" radius={[0, 4, 4, 0]} barSize={32}>
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[entry.severity as keyof typeof COLORS]} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
};

export default RemediationEffortChart;
