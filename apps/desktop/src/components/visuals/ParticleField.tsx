import { useEffect, useRef } from "react";

export type ParticleMode = "routes" | "graph" | "vault" | "flow";

const MODE_INDEX: Record<ParticleMode, number> = {
  routes: 0,
  graph: 1,
  vault: 2,
  flow: 3,
};

function random(index: number, salt: number) {
  const value = Math.sin(index * 91.17 + salt * 47.73) * 43758.5453;
  return value - Math.floor(value);
}

function compileShader(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

/**
 * A raw WebGL point field modeled after Snowboard's ambient renderer.
 *
 * The four morph targets are product-specific: API routes, a credential
 * dependency graph, the encrypted vault, and a live request flow. It is
 * visual only and never receives vault or activity data.
 */
export function ParticleField({
  density = 1,
  mode = "routes",
}: {
  density?: number;
  mode?: ParticleMode;
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const modeRef = useRef(mode);

  useEffect(() => {
    modeRef.current = mode;
  }, [mode]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const gl = canvas?.getContext("webgl", {
      alpha: true,
      antialias: false,
      powerPreference: "high-performance",
      premultipliedAlpha: false,
    });
    if (!canvas || !gl) {
      if (canvas) canvas.hidden = true;
      return;
    }

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const compact = Math.min(window.innerWidth, window.innerHeight) < 720;
    const count = Math.round((compact ? 5_500 : 14_000) * density);

    const vertexSource = `
      precision highp float;
      attribute vec3 aRoutes;
      attribute vec3 aGraph;
      attribute vec3 aVault;
      attribute vec3 aFlow;
      attribute vec3 aSeed;
      uniform float uState;
      uniform float uTime;
      uniform float uIntro;
      uniform float uPixelRatio;
      uniform vec2 uPointer;
      uniform mat3 uRotation;
      uniform mat4 uProjection;
      varying float vAlpha;
      varying float vBlue;
      varying float vGreen;

      float ease(float edge0, float edge1, float value) {
        float t = clamp((value - edge0) / (edge1 - edge0), 0.0, 1.0);
        return t * t * (3.0 - 2.0 * t);
      }

      void main() {
        float s1 = ease(0.0, 1.0, clamp(uState, 0.0, 1.0));
        float s2 = ease(0.0, 1.0, clamp(uState - 1.0, 0.0, 1.0));
        float s3 = ease(0.0, 1.0, clamp(uState - 2.0, 0.0, 1.0));
        vec3 point = mix(mix(mix(aRoutes, aGraph, s1), aVault, s2), aFlow, s3);
        vec3 scatter = (aSeed - 0.5) * vec3(8.0, 5.0, 5.0);
        point = mix(scatter, point, uIntro);

        float drift = uTime * 0.42 + aSeed.x * 6.283185;
        point += vec3(
          sin(drift + aSeed.y * 9.0),
          cos(drift * 0.73 + aSeed.z * 7.0),
          sin(drift * 0.61 + aSeed.x * 5.0)
        ) * 0.017;
        point = uRotation * point;

        vec2 delta = point.xy - uPointer;
        float distanceToPointer = length(delta);
        float push = smoothstep(0.82, 0.0, distanceToPointer) * 0.28;
        if (distanceToPointer > 0.0001) point.xy += normalize(delta) * push;

        vec4 view = vec4(point + vec3(0.42, 0.0, -5.2), 1.0);
        gl_Position = uProjection * view;
        float depth = clamp((view.z + 7.5) / 5.4, 0.34, 1.3);
        gl_PointSize = (0.75 + aSeed.y * 2.15) * depth * uPixelRatio;
        vAlpha = (0.16 + aSeed.z * 0.5) * mix(0.3, 1.0, uIntro);
        vBlue = step(0.76, aSeed.x);
        vGreen = step(0.945, aSeed.x);
      }
    `;

    const fragmentSource = `
      precision mediump float;
      varying float vAlpha;
      varying float vBlue;
      varying float vGreen;

      void main() {
        vec2 center = gl_PointCoord - 0.5;
        float alpha = smoothstep(0.5, 0.08, length(center)) * vAlpha;
        vec3 white = vec3(0.93, 0.95, 0.98);
        vec3 blue = vec3(0.16, 0.59, 1.0);
        vec3 green = vec3(0.45, 0.94, 0.70);
        vec3 color = mix(white, blue, vBlue);
        color = mix(color, green, vGreen);
        gl_FragColor = vec4(color * alpha, alpha);
      }
    `;

    const vertex = compileShader(gl, gl.VERTEX_SHADER, vertexSource);
    const fragment = compileShader(gl, gl.FRAGMENT_SHADER, fragmentSource);
    if (!vertex || !fragment) {
      canvas.hidden = true;
      return;
    }

    const program = gl.createProgram();
    if (!program) {
      canvas.hidden = true;
      return;
    }
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      canvas.hidden = true;
      return;
    }
    gl.useProgram(program);

    const routes = new Float32Array(count * 3);
    const graph = new Float32Array(count * 3);
    const vault = new Float32Array(count * 3);
    const flow = new Float32Array(count * 3);
    const seeds = new Float32Array(count * 3);
    const tau = Math.PI * 2;

    const graphNodes = Array.from({ length: 18 }, (_, index) => {
      if (index < 3) {
        return [(index - 1) * 0.68, (index % 2 === 0 ? -1 : 1) * 0.22, (index - 1) * 0.12];
      }
      const ringIndex = index - 3;
      const angle = (ringIndex / 15) * tau + (ringIndex % 3) * 0.08;
      return [
        Math.cos(angle) * (1.65 + (ringIndex % 2) * 0.28),
        Math.sin(angle) * (1.02 + (ringIndex % 3) * 0.12),
        Math.sin(angle * 2.0) * 0.48,
      ];
    });

    for (let index = 0; index < count; index += 1) {
      const offset = index * 3;
      const r1 = random(index, 1);
      const r2 = random(index, 2);
      const r3 = random(index, 3);
      seeds[offset] = r1;
      seeds[offset + 1] = r2;
      seeds[offset + 2] = r3;

      // Route topology: parallel request paths with sparse convergence points.
      const routeIndex = Math.floor(r1 * 13);
      const routeT = r2 < 0.22 ? Math.round(r3 * 4) / 4 : r3;
      const routeWave = Math.sin(routeT * tau * (1 + (routeIndex % 3)) + routeIndex) * 0.11;
      routes[offset] = (routeT - 0.5) * 5.0 + (r1 - 0.5) * 0.025;
      routes[offset + 1] = (routeIndex - 6) * 0.19 + routeWave + (r2 - 0.5) * 0.04;
      routes[offset + 2] = Math.sin(routeT * Math.PI + routeIndex * 0.7) * 0.62;

      // Credential graph: particles sit on dependency edges and around nodes.
      const nodeA = Math.floor(r1 * graphNodes.length);
      const nodeB = (nodeA + 1 + Math.floor(r2 * 7)) % graphNodes.length;
      const edgeT = r3 < 0.18 ? 0 : r3;
      const a = graphNodes[nodeA];
      const b = graphNodes[nodeB];
      graph[offset] = a[0] + (b[0] - a[0]) * edgeT + (r2 - 0.5) * 0.035;
      graph[offset + 1] = a[1] + (b[1] - a[1]) * edgeT + (r1 - 0.5) * 0.035;
      graph[offset + 2] = a[2] + (b[2] - a[2]) * edgeT + (r3 - 0.5) * 0.035;

      // Vault: quantized latitude and longitude rings around an encrypted core.
      let theta = r1 * tau;
      let phi = Math.acos(2 * r2 - 1);
      if (r3 < 0.5) phi = (Math.round((phi / Math.PI) * 14) / 14) * Math.PI;
      else theta = (Math.round((theta / tau) * 22) / 22) * tau;
      const vaultRadius = 1.48 + (r3 - 0.5) * 0.045;
      vault[offset] = Math.sin(phi) * Math.cos(theta) * vaultRadius;
      vault[offset + 1] = Math.cos(phi) * vaultRadius;
      vault[offset + 2] = Math.sin(phi) * Math.sin(theta) * vaultRadius;

      // Live flow: a four-lane request tunnel that tightens at the gateway.
      const flowT = r1;
      const arm = (index % 4) * (tau / 4);
      const flowAngle = arm + flowT * 4.4 + (r2 - 0.5) * 0.28;
      const flowRadius = 0.18 + Math.sin(flowT * Math.PI) * 0.88;
      flow[offset] = (flowT - 0.5) * 4.8;
      flow[offset + 1] = Math.cos(flowAngle) * flowRadius * 0.72;
      flow[offset + 2] = Math.sin(flowAngle) * flowRadius;
    }

    const bindAttribute = (name: string, data: Float32Array) => {
      const buffer = gl.createBuffer();
      const location = gl.getAttribLocation(program, name);
      if (!buffer || location < 0) return;
      gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
      gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
      gl.enableVertexAttribArray(location);
      gl.vertexAttribPointer(location, 3, gl.FLOAT, false, 0, 0);
    };

    bindAttribute("aRoutes", routes);
    bindAttribute("aGraph", graph);
    bindAttribute("aVault", vault);
    bindAttribute("aFlow", flow);
    bindAttribute("aSeed", seeds);

    const stateLocation = gl.getUniformLocation(program, "uState");
    const timeLocation = gl.getUniformLocation(program, "uTime");
    const introLocation = gl.getUniformLocation(program, "uIntro");
    const ratioLocation = gl.getUniformLocation(program, "uPixelRatio");
    const pointerLocation = gl.getUniformLocation(program, "uPointer");
    const rotationLocation = gl.getUniformLocation(program, "uRotation");
    const projectionLocation = gl.getUniformLocation(program, "uProjection");

    gl.disable(gl.DEPTH_TEST);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE);
    gl.clearColor(0, 0, 0, 0);

    let width = window.innerWidth;
    let height = window.innerHeight;
    let pixelRatio = 1;
    const fieldOfView = (43 * Math.PI) / 180;

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      pixelRatio = Math.min(window.devicePixelRatio || 1, 1.8);
      canvas.width = Math.round(width * pixelRatio);
      canvas.height = Math.round(height * pixelRatio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      gl.viewport(0, 0, canvas.width, canvas.height);

      const aspect = canvas.width / Math.max(canvas.height, 1);
      const f = 1 / Math.tan(fieldOfView / 2);
      const near = 0.1;
      const far = 20;
      gl.uniformMatrix4fv(
        projectionLocation,
        false,
        new Float32Array([
          f / aspect,
          0,
          0,
          0,
          0,
          f,
          0,
          0,
          0,
          0,
          (far + near) / (near - far),
          -1,
          0,
          0,
          (2 * far * near) / (near - far),
          0,
        ]),
      );
      gl.uniform1f(ratioLocation, pixelRatio);
    };

    const pointer = { x: 0, y: 0, targetX: 0, targetY: 0 };
    const onPointerMove = (event: PointerEvent) => {
      pointer.targetX = (event.clientX / Math.max(width, 1)) * 2 - 1;
      pointer.targetY = -((event.clientY / Math.max(height, 1)) * 2 - 1);
    };
    const onPointerLeave = () => {
      pointer.targetX = 0;
      pointer.targetY = 0;
    };

    let animationFrame = 0;
    let running = true;
    let state = MODE_INDEX[modeRef.current];
    let intro = reduced ? 1 : 0;
    let start = performance.now();
    const halfHeight = Math.tan(fieldOfView / 2) * 5.2;

    const draw = (now: number) => {
      if (!running) return;
      const time = (now - start) / 1000;
      if (!reduced && intro < 1) intro = Math.min(1, time / 1.7);
      const easedIntro = 1 - Math.pow(1 - intro, 3);

      pointer.x += (pointer.targetX - pointer.x) * 0.045;
      pointer.y += (pointer.targetY - pointer.y) * 0.045;
      state += (MODE_INDEX[modeRef.current] - state) * 0.052;

      const rotationY = (reduced ? 0 : time * 0.035) + pointer.x * 0.21;
      const rotationX = -pointer.y * 0.12 + (reduced ? 0 : Math.sin(time * 0.09) * 0.025);
      const cy = Math.cos(rotationY);
      const sy = Math.sin(rotationY);
      const cx = Math.cos(rotationX);
      const sx = Math.sin(rotationX);

      gl.uniformMatrix3fv(
        rotationLocation,
        false,
        new Float32Array([cy, sx * sy, -cx * sy, 0, cx, sx, sy, -sx * cy, cx * cy]),
      );
      gl.uniform2f(
        pointerLocation,
        pointer.x * halfHeight * (canvas.width / Math.max(canvas.height, 1)),
        pointer.y * halfHeight,
      );
      gl.uniform1f(stateLocation, state);
      gl.uniform1f(timeLocation, reduced ? 0 : time);
      gl.uniform1f(introLocation, easedIntro);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.POINTS, 0, count);
      animationFrame = requestAnimationFrame(draw);
    };

    const onVisibilityChange = () => {
      running = !document.hidden;
      if (running) {
        start = performance.now();
        animationFrame = requestAnimationFrame(draw);
      }
    };

    const onContextLost = (event: Event) => {
      event.preventDefault();
      running = false;
      canvas.hidden = true;
    };

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    document.documentElement.addEventListener("pointerleave", onPointerLeave);
    document.addEventListener("visibilitychange", onVisibilityChange);
    canvas.addEventListener("webglcontextlost", onContextLost);
    animationFrame = requestAnimationFrame(draw);

    return () => {
      running = false;
      cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onPointerMove);
      document.documentElement.removeEventListener("pointerleave", onPointerLeave);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      canvas.removeEventListener("webglcontextlost", onContextLost);
      gl.deleteProgram(program);
      gl.deleteShader(vertex);
      gl.deleteShader(fragment);
    };
  }, [density]);

  return <canvas ref={canvasRef} className="particle-field" aria-hidden="true" />;
}
