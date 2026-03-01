# Contributing

## Development Setup

1. Clone the repository.
2. Create a virtual environment: `python3 -m venv .venv`
3. Activate the virtual environment.
4. Install the project in editable mode with development dependencies:
   ```bash
   pip install -e .
   ```

## Project Structure

The project follows a standard `src/` layout:
- `src/web_health_scanner/`: Main package source code.
- `tests/`: Test suite (using `unittest`).
- `docs/`: Project documentation and security logs.

## Running Tests

Tests are located in the `tests/` directory and can be run using the standard Python `unittest` module:
```bash
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
python3 -m unittest discover tests
```

## Code Style

We use `ruff` for code formatting and linting. Please ensure your code is formatted before submitting a pull request.
