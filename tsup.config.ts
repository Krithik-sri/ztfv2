import { defineConfig } from 'tsup';

export default defineConfig({
    entry: [
        'src/index.ts',
        'src/middleware/fastify.ts',
        'src/middleware/koa.ts',
        'src/middleware/hono.ts',
    ],
    format: ['cjs', 'esm'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    external: ['fastify', 'koa', 'hono'],
});
