<!-- SPDX-License-Identifier: MPL-2.0 -->

# Troubleshooting Guide

This guide provides solutions to common issues you might encounter while using or developing AI Trust.

## Installation Issues

### Error: Command "python setup.py egg_info" failed

**Symptoms**:
- Error during package installation
- Missing dependencies

**Solution**:
```bash
# Install build dependencies
pip install --upgrade pip setuptools wheel

# Try installing again
pip install -e .
```

### Module Not Found Errors

**Symptoms**:

- `ModuleNotFoundError` when running the application
- Missing dependencies

**Solution**:

```bash
# Install all dependencies
pip install -e '.[dev,server,crypto]'

# Or install a specific dependency
pip install missing-package-name
```

## Runtime Issues

### Port Already in Use

**Symptoms**:

- `OSError: [Errno 98] Address already in use`
- Can't start the server

**Solution**:

```bash
# Find and kill the process using the port
lsof -i :8000
kill -9 <PID>

# Or change the port in .env
```

### Database Connection Issues

**Symptoms**:

- Database connection errors
- Can't access the database

**Solution**:

- Check if the database server is running
- Verify the connection string in `.env`
- Check file permissions for SQLite databases

## Testing Issues

### Tests Failing

**Symptoms**:

- Tests fail with various errors
- Inconsistent test results

**Solution**:

```bash
# Run tests with more verbose output
pytest -v

# Run a specific test
pytest tests/unit/test_module.py::test_function

# Run with debug logging
pytest --log-cli-level=DEBUG
```

### Test Database Issues

**Symptoms**:

- Tests fail due to database issues
- Test data persists between test runs

**Solution**:

```bash
# Make sure to use a test database
# Check your test configuration in conftest.py or pytest.ini

# Clean up test databases
rm -f test_*.db
```

## Performance Issues

### Slow Test Suite

**Symptoms**:

- Tests run slowly
- Long test execution time

**Solution**:

```bash
# Run tests in parallel
pytest -n auto

# Only run tests that failed last time
pytest --lf

# Only run tests that haven't passed recently
pytest --ff
```

### Memory Leaks

**Symptoms**:

- Application uses more memory over time
- Crashes due to out of memory

**Solution**:

- Use a memory profiler:

```bash
pip install memory_profiler
python -m memory_profiler your_script.py
```

- Look for circular references
- Close database connections properly

## Debugging

### Debugging with pdb

Add this to your code to start a debugger:

```python
import pdb; pdb.set_trace()
```

### Debugging with VSCode

- Install the Python extension
- Add a breakpoint by clicking in the gutter
- Press F5 to start debugging

## Getting Help

If you can't resolve your issue:

- Check the documentation
- Search the issue tracker
- Open a new issue with:
  - A clear description of the problem
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment details
