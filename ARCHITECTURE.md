# Project Architecture & Structure

Overview of DarkCoder's project structure and design patterns.

## Project Structure

```
darkcoder-cli/
├── packages/                      # Monorepo packages
│   ├── cli/                       # Main CLI application
│   ├── core/                      # Core utilities and types
│   ├── sdk-typescript/            # TypeScript SDK
│   ├── test-utils/                # Shared testing utilities
│   └── vscode-ide-companion/      # VS Code extension
├── integration-tests/             # End-to-end tests
├── docs/                          # Documentation
├── scripts/                       # Build and utility scripts
├── BUILD.md                       # Build guide
├── SETUP.md                       # Setup instructions
├── CONTRIBUTING.md                # Contribution guidelines
├── package.json                   # Root package configuration
├── tsconfig.json                  # TypeScript configuration
└── README.md                      # Project overview
```

## Monorepo Structure

This is a **npm workspaces** monorepo with the following packages:

### `/packages/cli`

- **Main CLI application** for DarkCoder
- Command-line interface for security operations
- Houses the `start` entry point
- Contains command implementations and tool integrations

### `/packages/core`

- **Shared core utilities** used by other packages
- Type definitions and interfaces
- Security tool abstractions
- Common utilities and helpers

### `/packages/sdk-typescript`

- **TypeScript SDK** for programmatic use
- Exposes DarkCoder functionality as a library
- Useful for integration with other tools

### `/packages/test-utils`

- **Shared testing utilities** for consistent test setups
- Mock implementations
- Test helpers and fixtures

### `/packages/vscode-ide-companion`

- **VS Code extension** for IDE integration
- Enhanced developer experience in VS Code
- Built separately from main CLI

## Key Technologies

| Layer               | Technology   | Purpose                    |
| ------------------- | ------------ | -------------------------- |
| **Language**        | TypeScript   | Type-safe development      |
| **Runtime**         | Node.js v20+ | Server-side execution      |
| **Package Manager** | npm          | Dependency management      |
| **Build Tool**      | esbuild      | Fast bundling              |
| **Testing**         | Vitest       | Unit and integration tests |
| **Linting**         | ESLint       | Code quality               |
| **Formatting**      | Prettier     | Code formatting            |
| **Type Checking**   | TypeScript   | Static type checking       |

## Build Process

### Stage 1: Source Processing

- TypeScript compilation to JavaScript
- Tree-shaking and bundling via esbuild
- Asset copying (required data files)

### Stage 2: Memory Management

- Monitor heap usage
- Graceful garbage collection
- Support for constrained environments

### Stage 3: Artifact Generation

- CLI binary (`dist/cli.js`)
- Library artifacts
- Documentation updates

## Configuration Files

### Root Level

- **`tsconfig.json`**: TypeScript compiler options (strict mode enabled)
- **`package.json`**: Dependencies, scripts, workspace configuration
- **`eslint.config.js`**: ESLint rules and configuration
- **`.prettierrc.json`**: Code formatting rules

### Package Level

Each package has its own:

- `package.json`: Package metadata and dependencies
- `tsconfig.json`: Package-specific TypeScript options (extends root)
- `vitest.config.ts`: Test configuration

## Development Workflow

### Setup

1. `git clone` the repository
2. `npm install` to install dependencies
3. `npm run build` to build packages
4. `npm start` to run CLI

### Making Changes

1. Create feature branch: `git checkout -b feature/my-feature`
2. Make changes in appropriate package
3. Run tests: `npm test`
4. Run linting: `npm run lint`
5. Commit changes: `git commit -m "feat: description"`
6. Push and create PR

### Build Targets

- **`npm run build`**: Standard build (recommended)
- **`npm run build:managed`**: Memory-optimized build
- **`npm run build:all`**: Full build including sandbox and VS Code extension
- **`npm run build:packages`**: Rebuild workspace packages

## Testing Strategy

### Test Organization

- **Unit tests**: Near source files (`.test.ts`, `.spec.ts`)
- **Integration tests**: `integration-tests/` folder
- **E2E tests**: Long-running integration scenarios

### Running Tests

- **All tests**: `npm test`
- **Specific test**: `npm test -- path/to/test.ts`
- **Watch mode**: `npm test -- --watch`
- **Coverage**: `npm test -- --coverage`

## Dependency Management

### Workspaces

Uses npm workspaces for easy dependency management:

- Shared dependencies in root `package.json`
- Package-specific dependencies in package `package.json`
- Automatic hoisting of shared dependencies

### Patched Dependencies

- Uses `patch-package` for necessary patches
- Patches stored in `/patches` directory
- Applied during `postinstall` phase

## Memory Considerations

DarkCoder includes sophisticated memory management:

### Heap Size

- Configurable via `NODE_OPTIONS` environment variable
- Default: 8GB recommended for most systems
- Can be lowered to 2-4GB on constrained systems

### Garbage Collection

- Automatic GC configured in build scripts
- Monitor heap usage during long-running operations
- Support for Bun's `--smol` flag for minimal footprint

## Code Organization Principles

### Single Responsibility

- Each package has a focused purpose
- Clear separation of concerns
- Minimal interdependencies

### Type Safety

- Strict TypeScript mode enabled
- No implicit any
- Required return types

### Testing First

- Tests colocated with source
- High code coverage expected
- Integration tests for complex flows

### Documentation

- Inline code comments for complex logic
- README files in each package
- Architecture decisions documented

## Performance Optimization

### Build Performance

- Incremental builds via `tsc --incremental`
- Parallel test execution via Vitest
- esbuild for fast bundling

### Runtime Performance

- Lazy loading where applicable
- Streaming for large data
- Worker threads for heavy operations

## Scalability Considerations

### For New Features

1. Choose appropriate package (cli, core, sdk-typescript)
2. Add types to core if needed
3. Implement feature in chosen package
4. Add tests alongside code
5. Update documentation
6. Ensure no circular dependencies

### For New Packages

1. Create under `packages/new-package`
2. Add `package.json` with metadata
3. Add `tsconfig.json` extending root
4. Create `README.md`
5. Update root `package.json` workspaces array
6. Ensure clear purpose and API surface

## CI/CD Considerations

The project is designed for CI/CD with:

- Consistent builds across machines
- Testable in isolation
- Memory-managed for constrained runners
- Reproducible with npm ci

See `npm run test:ci` and `npm run lint:ci` for CI-specific commands.

## Debugging

### Enable Debug Mode

```bash
npm run debug
```

### Inspect Heap

```bash
node --inspect scripts/build.js
```

### Verbose Output

```bash
npm run build -- --verbose
```

## Related Documentation

- [CONTRIBUTING.md](./CONTRIBUTING.md) - How to contribute
- [BUILD.md](./BUILD.md) - Build troubleshooting
- [SETUP.md](./SETUP.md) - Development setup
- [docs/README.md](./docs/README.md) - Full documentation
