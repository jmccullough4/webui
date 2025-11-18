# CTG Node Backend

## Overview
CTG Node Backend is a Flask-based web application that provides network management, device licensing, and system monitoring capabilities.

## Running the Application

### Direct Execution (Recommended)
```bash
cd backend/wh
python3 app.py
```

### As a Python Module
```bash
cd backend
python3 -m wh.app
```

## Environment Variables

- `HOST_IP`: IP address to bind to (default: 127.0.0.1)
- `HOST_PORT`: Port to bind to (default: 8080)
- `SERVER_DEBUG`: Enable debug mode (default: False)
- `JWT_SECRET_KEY`: Secret key for JWT tokens
- `COMPANY_PUBLIC_KEY_PATH`: Path to company public key for licensing

## Package Structure

```
wh/
├── app.py               # Main Flask application
├── version.py           # Version information
├── license_manager.py   # Device licensing management
├── requirements.txt     # Python dependencies
├── routes/              # API route definitions
│   ├── __init__.py
│   └── license_routes.py
├── utils/               # Utility functions
│   └── __init__.py
├── scripts/             # Setup and utility scripts
│   ├── device_registration.py
│   ├── generate_ssl_cert.py
│   ├── setup_ssl.sh
│   └── ...
├── tests/               # Test files
│   └── ...
└── readmes/             # Documentation
    └── ...
```

## Troubleshooting

### Import Errors
If you encounter import errors like "attempted relative import with no known parent package", ensure you're running the application from the correct directory (`backend/wh/`) or use the module execution method.

### License System
The license management system is excluded from production builds. For development and testing, ensure the `license_manager.py` and related files are present.

## Development

### Adding New Routes
1. Create new route files in the `routes/` directory
2. Import them in `app.py` using absolute imports
3. Register blueprints with the Flask app

### Testing
```bash
cd backend
python -m pytest tests/
```

## Build and Deployment

The application can be built using the build script in the parent directory:

```bash
cd ../
./build.sh
```

This will create a `local_build` directory with the production-ready application.
