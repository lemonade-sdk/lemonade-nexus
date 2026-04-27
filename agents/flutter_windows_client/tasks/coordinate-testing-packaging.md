# Task: Coordinate Testing & Packaging

## Description
Manage test suite creation and MSIX packaging for distribution.

## Goal
Production-ready package with comprehensive test coverage.

## Steps

### 1. Testing Agent Engagement
- [ ] Review `../testing_agent/agent.md`
- [ ] Invoke Testing Agent with requirements
- [ ] Define coverage goals

### 2. Test Suite Development
- [ ] Unit tests (FFI, services, state)
- [ ] Widget tests (all views)
- [ ] Integration tests (full flows)
- [ ] Coverage analysis

### 3. Packaging Agent Engagement
- [ ] Review `../packaging_agent/agent.md`
- [ ] Invoke Packaging Agent with requirements
- [ ] Define distribution targets

### 4. MSIX Package Creation
- [ ] Configure msix_config
- [ ] Create package manifest
- [ ] Define capabilities
- [ ] Build MSIX

### 5. Code Signing
- [ ] Configure signing tool
- [ ] Obtain certificates
- [ ] Sign package
- [ ] Verify signature

### 6. Distribution Setup
- [ ] Windows Store prep
- [ ] Direct download config
- [ ] Update mechanism
- [ ] CI/CD pipeline

### 7. Final Validation
- [ ] Install test
- [ ] SmartScreen check
- [ ] Functionality verification
- [ ] Performance check

## Requirements
- Testing Agent available
- Packaging Agent available
- Code signing certificates
- CI/CD access

## Validation
- All tests pass
- 80%+ coverage
- MSIX installs cleanly
- No SmartScreen warnings

## Estimated Time
10-12 hours (with agents)

## Dependencies
- All development tasks complete
- FFI, UI, State, Windows integration done

## Outputs
- Complete test suite
- MSIX package
- Signed bundle
- Distribution ready
