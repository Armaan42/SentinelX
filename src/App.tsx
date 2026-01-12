import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "@/pages/Index";
import Demo from "./pages/Demo";
import FeatureDetail from "./pages/FeatureDetail";
import ProblemDetail from "@/pages/ProblemDetail";
import ComparisonPage from "./pages/ComparisonPage";
import NotFound from "./pages/NotFound";
import AnalyticsDetail from "./pages/AnalyticsDetail";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/demo" element={<Demo />} />
          <Route path="/feature/:featureId" element={<FeatureDetail />} />
          <Route path="/problem/:problemId" element={<ProblemDetail />} />
          <Route path="/comparison" element={<ComparisonPage />} />
          <Route path="/analytics/:analysisId" element={<AnalyticsDetail />} />
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
