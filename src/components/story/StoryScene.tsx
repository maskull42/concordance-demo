import { useEffect, useRef, type ReactNode } from "react";
import { useInView } from "framer-motion";

export function StoryScene({
  id,
  eyebrow,
  title,
  graphic,
  children,
}: {
  id: string;
  eyebrow?: string;
  title: string;
  graphic: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="story-scene story-scene--split" aria-labelledby={`${id}-title`}>
      <header className="story-scene-header">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h2 id={`${id}-title`}>{title}</h2>
      </header>
      <div className="story-scene-grid">
        <div className="story-scene-sticky">{graphic}</div>
        <div className="story-scene-steps">{children}</div>
      </div>
    </section>
  );
}

export function StoryStep({
  index,
  onActive,
  active,
  children,
}: {
  index: number;
  onActive: (index: number) => void;
  active: boolean;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { amount: 0.55 });

  useEffect(() => {
    if (inView) onActive(index);
  }, [inView, index, onActive]);

  return (
    <div className="story-step" data-active={active || undefined} ref={ref}>
      {children}
    </div>
  );
}
