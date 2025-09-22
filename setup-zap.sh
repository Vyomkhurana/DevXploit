#!/bin/bash
# DevXploit OWASP ZAP Docker Setup Script

echo "🐳 DevXploit ZAP Docker Setup"
echo "==============================="

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        echo "❌ Docker is not running. Please start Docker and try again."
        exit 1
    fi
    echo "✅ Docker is running"
}

# Function to stop existing ZAP container
stop_existing_zap() {
    echo "🛑 Stopping any existing ZAP containers..."
    docker stop devxploit-zap 2>/dev/null || true
    docker rm devxploit-zap 2>/dev/null || true
    echo "✅ Cleaned up existing containers"
}

# Function to start ZAP container
start_zap() {
    echo "🚀 Starting OWASP ZAP Docker container..."
    docker run -d \
        --name devxploit-zap \
        -p 8080:8080 \
        zaproxy/zap-stable \
        zap.sh -daemon -host 0.0.0.0 -port 8080 \
        -config api.addrs.addr.name=.* \
        -config api.addrs.addr.regex=true
    
    if [ $? -eq 0 ]; then
        echo "✅ ZAP container started successfully"
    else
        echo "❌ Failed to start ZAP container"
        exit 1
    fi
}

# Function to wait for ZAP to be ready
wait_for_zap() {
    echo "⏳ Waiting for ZAP to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8080/JSON/core/view/version/ > /dev/null 2>&1; then
            echo "✅ ZAP is ready!"
            return 0
        fi
        echo "   Attempt $i/30 - waiting for ZAP to start..."
        sleep 2
    done
    echo "❌ ZAP failed to start within 60 seconds"
    exit 1
}

# Function to show ZAP status
show_status() {
    echo ""
    echo "📊 ZAP Status:"
    echo "=============="
    docker ps | grep devxploit-zap
    echo ""
    echo "🔗 ZAP API: http://localhost:8080"
    echo "🧪 Test: curl http://localhost:8080/JSON/core/view/version/"
    echo ""
}

# Main execution
case "${1:-start}" in
    "start")
        check_docker
        stop_existing_zap
        start_zap
        wait_for_zap
        show_status
        echo "🎉 DevXploit ZAP setup complete! You can now run: npm start"
        ;;
    "stop")
        echo "🛑 Stopping ZAP container..."
        docker stop devxploit-zap
        docker rm devxploit-zap
        echo "✅ ZAP stopped and removed"
        ;;
    "status")
        echo "📊 ZAP Container Status:"
        docker ps | grep devxploit-zap || echo "❌ ZAP container not running"
        if curl -s http://localhost:8080/JSON/core/view/version/ > /dev/null 2>&1; then
            echo "✅ ZAP API is responding"
        else
            echo "❌ ZAP API not responding"
        fi
        ;;
    "restart")
        $0 stop
        sleep 2
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        echo ""
        echo "Commands:"
        echo "  start   - Start ZAP Docker container"
        echo "  stop    - Stop and remove ZAP container"
        echo "  status  - Check ZAP container status"
        echo "  restart - Restart ZAP container"
        exit 1
        ;;
esac