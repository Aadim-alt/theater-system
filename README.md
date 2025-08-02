# 🎬 Enhanced Theater Management System

Aadim’s production-ready **Theater Booking System**, built with FastAPI, PostgreSQL, Redis, and Docker. It features enterprise-grade security, real-time metrics, session management, performance monitoring, and a full test suite.

---

## 🌟 Features

- ✅ **FastAPI-based microservice architecture**
- 🔐 JWT authentication & bcrypt password hashing
- 🛡️ Rate limiting (Redis), secure sessions (Fernet encryption)
- 📊 Prometheus metrics and Grafana dashboards
- 🧪 Full test suite with `pytest`, `pytest-asyncio`
- 🐳 Docker & Kubernetes deployment ready
- 📦 Database migrations with rollback support
- 🛠️ Production CLI for health checks, reports, audits

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/theater-system.git
cd theater-system
2. Install requirements (for local testing)
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
Once running:

API Docs: http://localhost:8000/api/docs

Health Check: http://localhost:8000/health

Metrics: http://localhost:8000/metrics

Grafana: http://localhost:3000 (user: admin, pass: admin)

🧪 Run Tests
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
├── docker-compose.yml          # Services: app, redis, postgres, grafana
├── requirements.txt            # Python dependencies
├── nginx.conf                  # Reverse proxy + rate limiting
├── init.sql                    # DB init script
├── prometheus.yml              # Prometheus scrape config
├── alert_rules.yml             # Prometheus alerts
├── Makefile                    # Helpful commands
├── ssl/                        # Self-signed certs (dev only)
├── README.md                   # You're reading it!
└── LICENSE                     # Open source license



🛡️ Security & Performance
Encrypted JWT tokens and sessions

Rate limiting by endpoint/IP

CSP headers and strict host policies

Metrics exposed for Prometheus scraping

Alerting rules for response time, error rate, fraud detection

📦 Deployment Options
🐳 Docker Compose (default)

☁️ Kubernetes + Helm (production-ready)

🧩 Prometheus + Grafana integrated

🔄 CI/CD compatible via Makefile + deployment scripts




🤝 Contributing
Pull requests welcome! Please open an issue first to discuss what you'd like to change.

Want to add fraud scoring, loyalty system, or SMS/email integration? Let's collaborate!




📄 License
This project is licensed under the MIT License




💡 Author
Aadim Dhakal
💻 Freelancer | A CS Student | Security Enthusiast
📧 Contact: dhakalaadim@gmail.com
🔗 GitHub: github.com/Aadim-alt
