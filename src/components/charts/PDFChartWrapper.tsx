import { ReactNode } from 'react';

interface PDFChartWrapperProps {
  chartId: string;
  children: ReactNode;
  className?: string;
  backgroundColor?: string;
}

/**
 * Wrapper component that adds proper data-chart attributes for PDF export.
 * The html2canvas library uses these attributes to find and capture charts.
 */
const PDFChartWrapper = ({ 
  chartId, 
  children, 
  className = '',
  backgroundColor = '#ffffff'
}: PDFChartWrapperProps) => {
  return (
    <div 
      data-chart={chartId}
      className={`pdf-chart-container ${className}`}
      style={{ 
        backgroundColor,
        padding: '16px',
        borderRadius: '8px'
      }}
    >
      {children}
    </div>
  );
};

export default PDFChartWrapper;
