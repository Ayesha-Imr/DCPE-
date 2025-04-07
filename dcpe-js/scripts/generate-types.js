import { execSync } from 'child_process';

// First, install typescript and tsd-jsdoc if not already installed
try {
  execSync('npm install --save-dev typescript tsd-jsdoc');
  console.log('Installed typescript and tsd-jsdoc');
} catch (error) {
  console.error('Failed to install dependencies:', error);
  process.exit(1);
}

// Generate TypeScript definitions from JSDoc
try {
  execSync('npx tsd-jsdoc -o dist');
  console.log('Generated TypeScript definitions in dist/ folder');
} catch (error) {
  console.error('Failed to generate TypeScript definitions:', error);
  process.exit(1);
}