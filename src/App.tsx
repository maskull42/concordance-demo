import { dataset } from "@dataset";
import { LazyMotion, MotionConfig, domMax } from "framer-motion";
import { DatasetStatusNotice } from "./components/DatasetStatusNotice";
import { HonestyBanner } from "./components/HonestyBanner";
import { InspectPage } from "./components/InspectPage";
import { StoryPage } from "./components/story/StoryPage";
import { useHashRoute } from "./lib/router";
import type { Dataset } from "./lib/types";

const validatedDataset = dataset as Dataset;

export function App() {
  const route = useHashRoute(validatedDataset);

  return (
    <LazyMotion features={domMax} strict>
      <MotionConfig reducedMotion="user">
        <div className="min-h-screen bg-paper text-ink">
          <HonestyBanner />
          <DatasetStatusNotice dataset={validatedDataset} />

          {route.mode === "story" ? (
            <StoryPage dataset={validatedDataset} />
          ) : (
            <InspectPage dataset={validatedDataset} route={route} />
          )}

          <footer className="site-footer">
            <p>Concordance · static, cached, and inspectable</p>
            {route.mode === "story" ? (
              <a href="#/inspect">Inspect the full record</a>
            ) : (
              <a href="#/story">Back to the story</a>
            )}
          </footer>
        </div>
      </MotionConfig>
    </LazyMotion>
  );
}
