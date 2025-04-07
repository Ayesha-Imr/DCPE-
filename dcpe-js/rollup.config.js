import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import babel from '@rollup/plugin-babel';
import json from '@rollup/plugin-json';
import terser from '@rollup/plugin-terser';
import { readFileSync } from 'fs';
import nodePolyfills from 'rollup-plugin-polyfill-node'; // Updated import

// Import package.json using standard Node.js approach instead of ESM assertions
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default [
    // CommonJS (for Node) and ES module (for bundlers) build
    {
        input: 'src/index.js',
        output: [
            { file: pkg.main, format: 'cjs', sourcemap: true },
            { file: pkg.module, format: 'es', sourcemap: true }
        ],
        plugins: [
            resolve({ preferBuiltins: true }),
            commonjs(),
            json(),
            babel({
                babelHelpers: 'bundled',
                exclude: 'node_modules/**'
            })
        ],
        external: [
            ...Object.keys(pkg.dependencies || {}),
            ...Object.keys(pkg.peerDependencies || {})
        ]
    },
    // Browser-friendly UMD build
    {
        input: 'src/index.js',
        output: {
            name: 'dcpeJS',
            file: 'dist/dcpe-js.umd.js',
            format: 'umd',
            sourcemap: true,
            globals: {
                'crypto': 'crypto',
                'mathjs': 'math' // Specify global names for external modules
            }
        },
        plugins: [
            resolve({ browser: true }),
            commonjs(),
            json(),
            nodePolyfills(), // Updated plugin usage
            babel({
                babelHelpers: 'bundled',
                exclude: 'node_modules/**'
            }),
            terser()
        ]
    }
];