#!/usr/bin/env node
import { run } from '../src/cli.js';
run().catch((error) => {
    console.error(`\nUnexpected error: ${error.message}\n`);
    process.exitCode = 1;
});
