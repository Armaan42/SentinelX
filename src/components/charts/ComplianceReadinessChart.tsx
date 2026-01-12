import { RadialBarChart, RadialBar, Legend, ResponsiveContainer, Tooltip } from 'recharts';

interface ComplianceReadinessChartProps {
    data: {
        standard: string;
        score: number;
        fill: string;
    }[];
}

const ComplianceReadinessChart = ({ data }: ComplianceReadinessChartProps) => {
    const style = {
        top: '50%',
        right: 0,
        transform: 'translate(0, -50%)',
        lineHeight: '24px',
    };

    const CustomTooltip = ({ active, payload }: any) => {
        if (active && payload && payload.length) {
            return (
                <div className="bg-card border border-border rounded-lg p-3 shadow-lg">
                    <p className="font-semibold text-foreground">{payload[0].name}</p>
                    <p className="text-sm text-muted-foreground">
                        Readiness: <span className="font-bold text-foreground">{payload[0].value}%</span>
                    </p>
                </div>
            );
        }
        return null;
    };

    return (
        <div className="bg-card rounded-lg p-2 h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
                <RadialBarChart cx="40%" cy="50%" innerRadius="10%" outerRadius="80%" barSize={20} data={data}>
                    <RadialBar
                        label={{ position: 'insideStart', fill: '#fff', fontSize: 10 }}
                        background
                        dataKey="score"
                        cornerRadius={10}
                    />
                    <Legend iconSize={10} layout="vertical" verticalAlign="middle" wrapperStyle={style} />
                    <Tooltip content={<CustomTooltip />} />
                </RadialBarChart>
            </ResponsiveContainer>
        </div>
    );
};

export default ComplianceReadinessChart;
