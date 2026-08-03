(() => {
  const canvas = document.querySelector("#ambient-network");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  document.querySelectorAll(".reveal").forEach((element) => {
    if (reduceMotion || !window.IntersectionObserver) {
      element.classList.add("is-visible");
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.14 },
    );
    observer.observe(element);
  });

  if (!(canvas instanceof HTMLCanvasElement)) return;
  const gl = canvas.getContext("webgl", {
    alpha: true,
    antialias: false,
    depth: false,
    premultipliedAlpha: false,
  });
  if (!gl) {
    document.documentElement.classList.add("no-webgl");
    return;
  }

  const vertexSource = `
    precision highp float;
    attribute vec3 a_position;
    attribute float a_seed;
    uniform vec2 u_pointer;
    uniform float u_time;
    uniform float u_aspect;
    uniform float u_pixel_ratio;
    varying float v_seed;
    varying float v_alpha;

    void main() {
      float breathe = sin(u_time * .42 + a_seed * 19.0) * .008;
      vec3 point = a_position;
      point.xy *= 1.0 + breathe;
      point.x /= max(u_aspect, 1.0);

      vec2 delta = point.xy - u_pointer;
      float distanceToPointer = length(delta);
      float repel = smoothstep(.23, 0.0, distanceToPointer) * .075;
      point.xy += normalize(delta + vec2(.0001)) * repel;

      float perspective = 1.0 / max(.72, 1.18 - point.z * .2);
      point.xy *= perspective;
      gl_Position = vec4(point.xy, 0.0, 1.0);
      gl_PointSize = (1.05 + mod(a_seed * 31.0, 2.2)) * u_pixel_ratio * perspective;
      v_seed = a_seed;
      v_alpha = .26 + mod(a_seed * 17.0, .64);
    }
  `;

  const fragmentSource = `
    precision mediump float;
    varying float v_seed;
    varying float v_alpha;

    void main() {
      vec2 offset = gl_PointCoord - .5;
      float distanceFromCenter = length(offset);
      if (distanceFromCenter > .5) discard;
      float core = smoothstep(.5, .04, distanceFromCenter);
      vec3 blue = vec3(.16, .59, 1.0);
      vec3 green = vec3(.40, .90, .67);
      vec3 white = vec3(.93, .97, 1.0);
      vec3 tint = v_seed > .92 ? green : mix(blue, white, smoothstep(.42, .98, v_seed));
      gl_FragColor = vec4(tint, core * v_alpha);
    }
  `;

  function shader(type, source) {
    const compiled = gl.createShader(type);
    if (!compiled) return null;
    gl.shaderSource(compiled, source);
    gl.compileShader(compiled);
    if (!gl.getShaderParameter(compiled, gl.COMPILE_STATUS)) return null;
    return compiled;
  }

  const vertexShader = shader(gl.VERTEX_SHADER, vertexSource);
  const fragmentShader = shader(gl.FRAGMENT_SHADER, fragmentSource);
  if (!vertexShader || !fragmentShader) return;
  const program = gl.createProgram();
  if (!program) return;
  gl.attachShader(program, vertexShader);
  gl.attachShader(program, fragmentShader);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
  gl.useProgram(program);

  const compact = window.matchMedia("(max-width: 700px)").matches;
  const count = compact ? 6800 : 14800;
  const targetCount = 4;
  const targets = Array.from({ length: targetCount }, () => new Float32Array(count * 3));
  const current = new Float32Array(count * 3);
  const seeds = new Float32Array(count);
  let state = 0x9e3779b9;
  const random = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };

  const write = (target, index, x, y, z) => {
    const offset = index * 3;
    target[offset] = x;
    target[offset + 1] = y;
    target[offset + 2] = z;
  };

  for (let index = 0; index < count; index += 1) {
    const seed = random();
    const noise = () => (random() - 0.5) * 0.025;
    seeds[index] = seed;

    // API routes: quiet horizontal traffic lanes with branching segments.
    const lane = index % 13;
    const routeX = random() * 2.5 - 1.25;
    const routeY = (lane / 12 - 0.5) * 1.25 + Math.sin(routeX * 6 + lane) * 0.025;
    const branch = index % 17 === 0 ? Math.sin(routeX * 2.6) * 0.42 : 0;
    write(targets[0], index, routeX, routeY + branch + noise(), random() * 0.8 - 0.4);

    // Credential graph: particles cluster around a deterministic dependency map.
    const node = index % 11;
    const nodeAngle = (node / 11) * Math.PI * 2 + (node % 3) * 0.18;
    const centerRadius = node % 4 === 0 ? 0.25 : 0.7;
    const centerX = Math.cos(nodeAngle) * centerRadius;
    const centerY = Math.sin(nodeAngle) * centerRadius * 0.72;
    const localAngle = random() * Math.PI * 2;
    const localRadius = Math.pow(random(), 2.2) * 0.26;
    write(
      targets[1],
      index,
      centerX + Math.cos(localAngle) * localRadius,
      centerY + Math.sin(localAngle) * localRadius,
      random() * 0.7 - 0.35,
    );

    // Vault intelligence: a softly projected sphere with latitudinal structure.
    const longitude = random() * Math.PI * 2;
    const latitude = Math.acos(random() * 2 - 1);
    const radius = 0.67 + noise();
    write(
      targets[2],
      index,
      Math.cos(longitude) * Math.sin(latitude) * radius,
      Math.cos(latitude) * radius,
      Math.sin(longitude) * Math.sin(latitude) * radius,
    );

    // Live flow: route traffic converging through a local gateway tunnel.
    const depth = random() * 2 - 1;
    const tunnelAngle = random() * Math.PI * 2 + depth * 2.1;
    const tunnelRadius = 0.18 + (depth + 1) * 0.36;
    write(
      targets[3],
      index,
      Math.cos(tunnelAngle) * tunnelRadius,
      Math.sin(tunnelAngle) * tunnelRadius * 0.72,
      depth,
    );
  }

  current.set(targets[0]);
  const positionBuffer = gl.createBuffer();
  const seedBuffer = gl.createBuffer();
  const positionLocation = gl.getAttribLocation(program, "a_position");
  const seedLocation = gl.getAttribLocation(program, "a_seed");
  const pointerLocation = gl.getUniformLocation(program, "u_pointer");
  const timeLocation = gl.getUniformLocation(program, "u_time");
  const aspectLocation = gl.getUniformLocation(program, "u_aspect");
  const ratioLocation = gl.getUniformLocation(program, "u_pixel_ratio");

  gl.bindBuffer(gl.ARRAY_BUFFER, seedBuffer);
  gl.bufferData(gl.ARRAY_BUFFER, seeds, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(seedLocation);
  gl.vertexAttribPointer(seedLocation, 1, gl.FLOAT, false, 0, 0);

  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
  gl.disable(gl.DEPTH_TEST);
  gl.clearColor(0, 0, 0, 0);

  const pointer = { x: 4, y: 4, targetX: 4, targetY: 4 };
  const onPointerMove = (event) => {
    const rect = canvas.getBoundingClientRect();
    pointer.targetX = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.targetY = -(((event.clientY - rect.top) / rect.height) * 2 - 1);
  };
  const onPointerLeave = () => {
    pointer.targetX = 4;
    pointer.targetY = 4;
  };
  canvas.parentElement?.addEventListener("pointermove", onPointerMove, { passive: true });
  canvas.parentElement?.addEventListener("pointerleave", onPointerLeave, { passive: true });

  let width = 0;
  let height = 0;
  let pixelRatio = 1;
  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(1, Math.round(rect.width * pixelRatio));
    height = Math.max(1, Math.round(rect.height * pixelRatio));
    if (canvas.width !== width || canvas.height !== height) {
      canvas.width = width;
      canvas.height = height;
      gl.viewport(0, 0, width, height);
    }
  };
  window.addEventListener("resize", resize, { passive: true });
  resize();

  let frame = 0;
  const render = (now) => {
    const seconds = now * 0.001;
    const scrollPhase = Math.min(2.8, window.scrollY / Math.max(window.innerHeight, 1) * 2.8);
    const phase = reduceMotion ? 0 : (seconds * 0.085 + scrollPhase) % targetCount;
    const from = Math.floor(phase);
    const to = (from + 1) % targetCount;
    const rawMix = phase - from;
    const mix = rawMix * rawMix * (3 - 2 * rawMix);
    const source = targets[from];
    const destination = targets[to];
    for (let index = 0; index < current.length; index += 1) {
      current[index] = source[index] + (destination[index] - source[index]) * mix;
    }

    pointer.x += (pointer.targetX - pointer.x) * 0.075;
    pointer.y += (pointer.targetY - pointer.y) * 0.075;
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, current, gl.DYNAMIC_DRAW);
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 3, gl.FLOAT, false, 0, 0);
    gl.uniform2f(pointerLocation, pointer.x, pointer.y);
    gl.uniform1f(timeLocation, seconds);
    gl.uniform1f(aspectLocation, width / Math.max(height, 1));
    gl.uniform1f(ratioLocation, pixelRatio);
    gl.drawArrays(gl.POINTS, 0, count);
    if (!reduceMotion && document.visibilityState === "visible") frame = requestAnimationFrame(render);
  };

  frame = requestAnimationFrame(render);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && !reduceMotion) {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(render);
    }
  });
})();
