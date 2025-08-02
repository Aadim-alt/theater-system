# 🎬 Enhanced Theater Management System

Aadim’s production-ready **Theater Booking System**, built with **FastAPI**, **PostgreSQL**, **Redis**, and **Docker**. It features enterprise-grade security, real-time metrics, encrypted session management, performance monitoring, and a comprehensive test suite.

---

## 🌟 Top Features

### 🔐 Security
- JWT authentication with bcrypt password hashing  
- Rate limiting via Redis + SlowAPI  
- Session management (encrypted with Fernet)  
- Account lockout, fraud detection & audit logging  
- SQL injection prevention, security headers, HTTPS-ready

### 🚀 Performance & Scalability
- Fully asynchronous (async/await) architecture  
- PostgreSQL connection pooling via `asyncpg`  
- Redis caching with hit/miss stats  
- Query optimizer with EXPLAIN ANALYZE  
- Auto-scaling via Kubernetes & Helm charts

### 🧪 Testing Suite
- Unit, integration, performance & security tests  
- Powered by `pytest` + `pytest-asyncio`  
- Mocked Redis/database fixtures  
- Load tests for booking/fraud systems

### 📊 Observability & Monitoring
- Prometheus metrics & Grafana dashboards  
- Structured logs via `structlog`  
- Health check & `/metrics` endpoint  
- System health scoring with alerting

### ⚙️ DevOps & Deployment
- Multi-stage Docker builds & Compose  
- Kubernetes manifests + Helm support  
- NGINX reverse proxy with TLS + rate limits  
- Trivy security scans & Makefile CI scripts

### 📈 Business Logic & CLI
- CLI for DB migrations, cache stats, health checks  
- Real-time fraud scoring  
- Session auditing & login tracking  
- Future-proof for dynamic pricing, loyalty, etc.

---

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/theater-system.git
cd theater-system
2. Install dependencies (for local dev)
bash
Copy
Edit
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
3. Run with Docker
bash
Copy
Edit
docker-compose up --build
📡 Access Endpoints
Feature	URL
API Docs	http://localhost:8000/api/docs
Health Check	http://localhost:8000/health
Prometheus	http://localhost:8000/metrics
Grafana	http://localhost:3000 (admin:admin)

🧪 Running Tests
bash
Copy
Edit
pytest ticket.py -v
📁 Project Structure
csharp
Copy
Edit
theater-system/
├── app/
│   └── ticket.py               # Main application logic
├── tests/                      # Unit & integration tests
├── Dockerfile                  # Multi-stage Docker build
├── docker-compose.yml          # Services: app, Redis, Postgres, Grafana
├── requirements.txt            # Python dependencies
├── nginx.conf                  # Reverse proxy + rate limiting
├── init.sql                    # DB init script
├── prometheus.yml              # Prometheus scrape config
├── alert_rules.yml             # Prometheus alerting
├── Makefile                    # Developer commands
├── ssl/                        # Self-signed certs (dev only)
├── README.md                   # You're reading it!
└── LICENSE                     # Open source license
🛡️ Security & Performance
Encrypted JWT tokens & sessions

Per-endpoint/IP rate limiting

Security headers (CSP, HSTS, etc.)

Prometheus-exposed metrics

Alert rules for fraud, latency & errors

📦 Deployment Options
🐳 Docker Compose (local/dev)

☁️ Kubernetes + Helm (production)

📈 Prometheus + Grafana monitoring

🔁 CI/CD-ready with Makefile & deployment scripts

🤝 Contributing
Pull requests welcome! Please open an issue first to propose a change.

Have ideas like fraud scoring, loyalty systems, or SMS/email support? Let’s build it together.

📄 License
Licensed under the MIT License

💡 Author
Aadim Dhakal
🎓 CS Student • 💻 Freelancer • 🔐 Security Enthusiast
📧 Email: dhakalaadim@gmail.com
🔗 GitHub: github.com/Aadim-alt

csharp
Copy
Edit

Want help generating badges, previewing this in GitHub, or linking it with CI tools like GitHub Actions?
