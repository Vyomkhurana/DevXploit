# OWASP ZAP Docker Integration for DevXploit

## Quick Start

### 1. Start ZAP in Docker
```bash
# Start ZAP daemon in Docker (run this first)
docker run -d -p 8080:8080 --name devxploit-zap zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

# Or start with UI for debugging (optional)
docker run -d -p 8080:8080 -p 8090:8090 --name devxploit-zap-ui zaproxy/zap-stable zap.sh -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

### 2. Verify ZAP is Running
```bash
curl http://localhost:8080/JSON/core/view/version/
```

### 3. Start DevXploit
```bash
npm start
```

## Docker Commands

### Start ZAP
```bash
docker run -d \
  --name devxploit-zap \
  -p 8080:8080 \
  zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
```

### Stop ZAP
```bash
docker stop devxploit-zap
docker rm devxploit-zap
```

### Check ZAP Status
```bash
docker ps | grep zap
docker logs devxploit-zap
```

### Restart ZAP
```bash
docker restart devxploit-zap
```

## Integration Benefits

1. **Professional Setup**: Industry-standard approach
2. **No Local Installation**: ZAP runs in isolated container
3. **API Ready**: REST API immediately available on port 8080
4. **Resource Control**: Manage ZAP memory/CPU usage
5. **Easy Updates**: Pull latest ZAP versions easily

## Troubleshooting

### If ZAP won't start:
```bash
# Kill any existing ZAP containers
docker stop devxploit-zap 2>/dev/null || true
docker rm devxploit-zap 2>/dev/null || true

# Start fresh
docker run -d --name devxploit-zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

### If port 8080 is busy:
```bash
# Check what's using port 8080
netstat -ano | findstr :8080
# Kill the process or use different port like 8081
```