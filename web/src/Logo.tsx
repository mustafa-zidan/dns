// The hushdns mark: a 16 × 16 pixel block with an h and a dot, drawn in the
// theme's accent colors so it follows light and dark mode. web/public/favicon.svg
// and docs/theme/favicon.svg are the same drawing.

const BLOCK = "M2 1h12v1h-12zM1 2h14v1h-14zM1 3h14v1h-14zM1 4h14v1h-14zM1 5h14v1h-14zM1 6h14v1h-14zM1 7h14v1h-14zM1 8h14v1h-14zM1 9h14v1h-14zM1 10h14v1h-14zM1 11h14v1h-14zM1 12h14v1h-14zM1 13h14v1h-14zM2 14h12v1h-12z";
const H = "M3 3h2v1h-2zM3 4h2v1h-2zM3 5h2v1h-2zM3 6h6v1h-6zM3 7h7v1h-7zM3 8h2v1h-2zM8 8h2v1h-2zM3 9h2v1h-2zM8 9h2v1h-2zM3 10h2v1h-2zM8 10h2v1h-2zM3 11h2v1h-2zM8 11h2v1h-2zM3 12h2v1h-2zM8 12h2v1h-2z";
const DOT = "M12 11h2v1h-2zM12 12h2v1h-2z";

export function Logo(props: { size?: number }) {
  const size = props.size ?? 24;
  return (
    <svg className="logo" width={size} height={size} viewBox="0 0 16 16" shapeRendering="crispEdges" aria-hidden="true">
      <path className="logo-block" d={BLOCK} />
      <path className="logo-h" d={H} />
      <path className="logo-dot" d={DOT} />
    </svg>
  );
}
