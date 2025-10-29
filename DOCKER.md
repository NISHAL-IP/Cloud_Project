# Docker Setup Guide

This guide explains how to containerize and run your Cloud Project using Docker.

## Prerequisites

- Docker Desktop installed on your machine
- Docker Compose (included with Docker Desktop)

## Project Structure

```
Cloud_Project/
├── backend/                 # Node.js Express API
│   ├── Dockerfile
│   ├── .dockerignore
│   └── ...
├── frontend/my-react-app/   # React Vite app
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── .dockerignore
│   └── ...
├── docker-compose.yml       # Orchestration
├── docker.env.example       # Environment variables template
└── DOCKER.md               # This file
```

## Quick Start

1. **Copy environment variables:**
   ```bash
   cp docker.env.example .env
   ```

2. **Edit the `.env` file with your actual values:**
   - Database connection details
   - Azure service credentials (optional)
   - Twilio credentials (optional)

3. **Build and start the services:**
   ```bash
   docker-compose up --build
   ```

4. **Access the application:**
   - Frontend: http://localhost:80
   - Backend API: http://localhost:3000
   - Health check: http://localhost:3000/health

## Services

### Backend Service
- **Image**: Custom Node.js 18 Alpine
- **Port**: 3000
- **Features**:
  - Express.js API server
  - Azure SQL Database connection
  - Authentication endpoints
  - Admin dashboard API
  - Push notifications (Azure/Twilio)
  - Health checks

### Frontend Service
- **Image**: Multi-stage build (Node.js → Nginx)
- **Port**: 80
- **Features**:
  - React application built with Vite
  - Served by Nginx
  - Client-side routing support
  - Gzip compression
  - Security headers

## Environment Variables

### Required
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_SERVER`: Database server hostname
- `DB_DATABASE`: Database name
- `DB_PORT`: Database port (default: 1433)

### Optional
- `FRONTEND_ORIGIN`: CORS origin (default: http://localhost:5173)
- Azure Notification Hubs credentials
- Azure Communication Services credentials
- Twilio credentials

## Docker Commands

### Development
```bash
# Start services
docker-compose up

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Rebuild and start
docker-compose up --build
```

### Production
```bash
# Build production images
docker-compose build

# Start production services
docker-compose up -d

# Scale services
docker-compose up -d --scale backend=2
```

### Maintenance
```bash
# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# View service status
docker-compose ps

# Execute commands in containers
docker-compose exec backend npm install
docker-compose exec frontend ls -la
```

## Troubleshooting

### Common Issues

1. **Port conflicts:**
   - Change ports in `docker-compose.yml` if 80 or 3000 are in use

2. **Database connection errors:**
   - Verify database credentials in `.env`
   - Ensure database server allows connections from Docker

3. **Build failures:**
   - Check Dockerfile syntax
   - Verify all dependencies are listed in package.json

4. **Frontend not loading:**
   - Check if backend is running and accessible
   - Verify CORS settings

### Logs and Debugging

```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs backend
docker-compose logs frontend

# Follow logs in real-time
docker-compose logs -f backend

# Check container health
docker-compose ps
```

### Performance Optimization

1. **Multi-stage builds**: Frontend uses multi-stage build to reduce image size
2. **Layer caching**: Package files copied first for better Docker layer caching
3. **Non-root user**: Backend runs as non-root user for security
4. **Health checks**: Both services include health checks for monitoring

## Security Considerations

- Backend runs as non-root user
- Frontend served with security headers
- Environment variables used for sensitive data
- Health checks implemented for monitoring

## Next Steps

1. Set up CI/CD pipeline for automated deployments
2. Configure production environment variables
3. Set up monitoring and logging
4. Implement backup strategies for database
5. Consider using Docker Swarm or Kubernetes for production scaling
