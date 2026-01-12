import { useRef, useState, useEffect } from "react";
import { ZoomIn, ZoomOut, Maximize, Move } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ZoomPanViewerProps {
    children: React.ReactNode;
}

export const ZoomPanViewer = ({ children }: ZoomPanViewerProps) => {
    const [scale, setScale] = useState(1);
    const [position, setPosition] = useState({ x: 0, y: 0 });
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

    const containerRef = useRef<HTMLDivElement>(null);

    const handleZoomIn = () => setScale((s) => Math.min(s * 1.2, 5));
    const handleZoomOut = () => setScale((s) => Math.max(s / 1.2, 0.5));
    const handleReset = () => {
        setScale(1);
        setPosition({ x: 0, y: 0 });
    };

    const handleMouseDown = (e: React.MouseEvent) => {
        setIsDragging(true);
        setDragStart({ x: e.clientX - position.x, y: e.clientY - position.y });
    };

    const handleMouseMove = (e: React.MouseEvent) => {
        if (!isDragging) return;
        setPosition({
            x: e.clientX - dragStart.x,
            y: e.clientY - dragStart.y,
        });
    };

    const handleMouseUp = () => setIsDragging(false);
    const handleMouseLeave = () => setIsDragging(false);

    // Wheel zoom support
    const handleWheel = (e: React.WheelEvent) => {
        // Small debounce or check for Ctrl key could be better, but direct zoom is intuitive for charts
        // Prevent default scrolling to allow zoom
        if (e.ctrlKey || e.metaKey) {
            // e.preventDefault(); // React synthetic events can't preventDefault quickly enough for wheel sometimes, but let's try
            const delta = e.deltaY * -0.01;
            const newScale = Math.min(Math.max(scale + delta, 0.5), 5);
            setScale(newScale);
        }
    };

    return (
        <div className="relative w-full h-full overflow-hidden bg-[#0d1117] group">
            {/* Controls */}
            <div className="absolute top-4 right-4 z-50 flex flex-col gap-2 bg-black/50 backdrop-blur p-2 rounded-lg border border-white/10 opacity-0 group-hover:opacity-100 transition-opacity">
                <Button size="icon" variant="ghost" className="h-8 w-8 text-white hover:bg-white/20" onClick={handleZoomIn} title="Zoom In">
                    <ZoomIn className="h-4 w-4" />
                </Button>
                <Button size="icon" variant="ghost" className="h-8 w-8 text-white hover:bg-white/20" onClick={handleZoomOut} title="Zoom Out">
                    <ZoomOut className="h-4 w-4" />
                </Button>
                <div className="h-px bg-white/10 my-1" />
                <Button size="icon" variant="ghost" className="h-8 w-8 text-white hover:bg-white/20" onClick={handleReset} title="Reset View">
                    <Maximize className="h-4 w-4" />
                </Button>
            </div>

            {/* Drag Hint */}
            <div className={`absolute bottom-4 left-1/2 -translate-x-1/2 z-40 bg-black/40 backdrop-blur px-3 py-1 rounded-full text-xs text-white/50 pointer-events-none transition-opacity ${isDragging ? 'opacity-0' : 'opacity-100'}`}>
                <div className="flex items-center gap-2">
                    <Move className="w-3 h-3" />
                    <span>Drag to Pan • Ctrl+Scroll to Zoom</span>
                </div>
            </div>

            <div
                ref={containerRef}
                className={`w-full h-full flex items-center justify-center cursor-move transition-transform duration-75 ease-linear`}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseLeave}
                onWheel={handleWheel}
            >
                <div
                    style={{
                        transform: `translate(${position.x}px, ${position.y}px) scale(${scale})`,
                        transition: isDragging ? 'none' : 'transform 0.2s ease-out',
                        transformOrigin: 'center',
                    }}
                    className="p-10" // Add padding so it starts with some breathing room
                >
                    {children}
                </div>
            </div>
        </div>
    );
};
