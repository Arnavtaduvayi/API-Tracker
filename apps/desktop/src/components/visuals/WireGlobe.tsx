// Decorative wireframe globe (react-three-fiber). Purely visual — it renders
// no vault data and makes no backend calls. Everything runs locally on the
// GPU; nothing is fetched over the network.
//
// The look is the reference brand language: a dark lat/long wire sphere with
// a handful of glowing accent nodes slowly orbiting it.

import { useMemo, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";

/** Builds clean latitude/longitude ring lines (no triangulation diagonals). */
function useLatLongGeometry(radius: number, lats: number, longs: number, segments = 128) {
  return useMemo(() => {
    const points: number[] = [];

    // Latitude rings (horizontal circles), skipping the poles.
    for (let i = 1; i < lats; i++) {
      const phi = (i / lats) * Math.PI;
      const r = Math.sin(phi) * radius;
      const y = Math.cos(phi) * radius;
      for (let s = 0; s < segments; s++) {
        const t0 = (s / segments) * Math.PI * 2;
        const t1 = ((s + 1) / segments) * Math.PI * 2;
        points.push(Math.cos(t0) * r, y, Math.sin(t0) * r);
        points.push(Math.cos(t1) * r, y, Math.sin(t1) * r);
      }
    }

    // Longitude rings (vertical half-circles through the poles).
    for (let i = 0; i < longs; i++) {
      const theta = (i / longs) * Math.PI * 2;
      for (let s = 0; s < segments; s++) {
        const p0 = (s / segments) * Math.PI;
        const p1 = ((s + 1) / segments) * Math.PI;
        const r0 = Math.sin(p0) * radius;
        const r1 = Math.sin(p1) * radius;
        points.push(Math.cos(theta) * r0, Math.cos(p0) * radius, Math.sin(theta) * r0);
        points.push(Math.cos(theta) * r1, Math.cos(p1) * radius, Math.sin(theta) * r1);
      }
    }

    const geom = new THREE.BufferGeometry();
    geom.setAttribute("position", new THREE.Float32BufferAttribute(points, 3));
    return geom;
  }, [radius, lats, longs, segments]);
}

/** Deterministic pseudo-random so the node layout is stable across renders. */
function seeded(i: number) {
  const x = Math.sin(i * 127.1) * 43758.5453;
  return x - Math.floor(x);
}

function Nodes({ radius, count, color }: { radius: number; count: number; color: string }) {
  const positions = useMemo(() => {
    const out: [number, number, number][] = [];
    for (let i = 0; i < count; i++) {
      const u = seeded(i + 1);
      const v = seeded(i + 97);
      const theta = u * Math.PI * 2;
      const phi = Math.acos(2 * v - 1);
      out.push([
        Math.sin(phi) * Math.cos(theta) * radius,
        Math.cos(phi) * radius,
        Math.sin(phi) * Math.sin(theta) * radius,
      ]);
    }
    return out;
  }, [radius, count]);

  return (
    <group>
      {positions.map((p, i) => (
        <mesh key={i} position={p}>
          <sphereGeometry args={[0.028, 12, 12]} />
          <meshBasicMaterial color={color} toneMapped={false} />
        </mesh>
      ))}
    </group>
  );
}

function Globe({ accent, wire }: { accent: string; wire: string }) {
  const group = useRef<THREE.Group>(null);
  const geometry = useLatLongGeometry(1.35, 14, 24);

  useFrame((state, delta) => {
    if (!group.current) return;
    group.current.rotation.y += delta * 0.12;
    // Gentle parallax toward the pointer, clamped so it never feels jumpy.
    const px = state.pointer.x * 0.18;
    const py = state.pointer.y * 0.12;
    group.current.rotation.x += (py - group.current.rotation.x) * 0.04;
    group.current.position.x += (px - group.current.position.x) * 0.04;
  });

  return (
    <group ref={group} rotation={[0.32, 0, 0.14]}>
      <lineSegments geometry={geometry}>
        <lineBasicMaterial color={wire} transparent opacity={0.34} toneMapped={false} />
      </lineSegments>
      {/* Inner dark core so the far side of the wire reads as "behind". */}
      <mesh>
        <sphereGeometry args={[1.32, 48, 48]} />
        <meshBasicMaterial color="#0b0715" transparent opacity={0.82} />
      </mesh>
      <Nodes radius={1.36} count={9} color={accent} />
    </group>
  );
}

export function WireGlobe({
  className,
  accent = "#f2415a",
  wire = "#8f86c9",
}: {
  className?: string;
  accent?: string;
  wire?: string;
}) {
  return (
    <div className={className} aria-hidden="true">
      <Canvas
        camera={{ position: [0, 0, 4.2], fov: 45 }}
        dpr={[1, 2]}
        gl={{ antialias: true, alpha: true }}
      >
        <Globe accent={accent} wire={wire} />
      </Canvas>
    </div>
  );
}
