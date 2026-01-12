import { useEffect, useRef, useState } from 'react';
import mermaid from 'mermaid';

interface MermaidDiagramProps {
    chart: string;
}

const MermaidDiagram = ({ chart }: MermaidDiagramProps) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const [html, setHtml] = useState<string>('');

    useEffect(() => {
        // Initialize mermaid with custom dark theme to match SentinelX aesthetics
        mermaid.initialize({
            startOnLoad: false,
            theme: 'base',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
            securityLevel: 'loose',
            themeVariables: {
                darkMode: true,
                background: '#0d1117',
                primaryColor: '#3b82f6',     // blue-500
                primaryTextColor: '#e2e8f0', // slate-200
                primaryBorderColor: '#3b82f6',
                lineColor: '#94a3b8',        // slate-400
                secondaryColor: '#1e293b',   // slate-800
                tertiaryColor: '#0f172a',    // slate-900
                noteBkgColor: '#1e293b',
                noteTextColor: '#94a3b8'
            }
        });

        const renderChart = async () => {
            try {
                const id = `mermaid-${Math.random().toString(36).substr(2, 9)}`;
                // mermaid.render returns an object { svg } in newer versions
                const result = await mermaid.render(id, chart);
                setHtml(result.svg);
            } catch (error) {
                console.error('Mermaid render error:', error);
                // Fallback or error state could go here
                setHtml(`<div class="text-red-500 text-xs p-4">Error rendering chart</div>`);
            }
        };

        renderChart();
    }, [chart]);

    return (
        <div
            ref={containerRef}
            className="w-full h-full flex items-center justify-center p-4 bg-[#0d1117] rounded-xl overflow-auto custom-mermaid-scroll"
            dangerouslySetInnerHTML={{ __html: html }}
        />
    );
};

export default MermaidDiagram;
