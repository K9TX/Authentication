# SecureAuth - Full-Stack Authentication System

A production-ready, highly optimized authentication system with Django REST Framework backend and React frontend.

## 📦 Installation

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip
- npm

### Backend Setup

1. Navigate to server directory:

```bash
cd server
```

2. Create virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create `.env` file:

```bash
cp .env.example .env
```

5. Configure `.env`:

6. Run migrations:

```bash
python manage.py migrate
```

7. Create superuser (optional):

```bash
python manage.py createsuperuser
```

8. Run development server:

```bash
python manage.py runserver
```

Backend will run on `http://localhost:8000`

### Frontend Setup

1. Navigate to client directory:

```bash
cd client
```

2. Install dependencies:

```bash
npm install
```

3. Create `.env` file:

```bash
cp .env.example .env
```

4. Configure `.env`:

5. Run development server:

```bash
npm run dev
```

Frontend will run on `http://localhost:5173`
