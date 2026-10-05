# CodeIgniter 4 Shield Demo

Demo app untuk testing Ganadev CodeIgniter 4 Shield.

## Instalasi

```bash
cd examples/codeigniter4-demo
composer install
cp .env.example .env
php spark migrate --all
php spark serve
```

## Testing

### Normal Traffic
```bash
curl http://localhost:8080/home
```

### Blocked (.env probe)
```bash
curl http://localhost:8080/.env
```

### SQL Injection
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin'+UNION+SELECT+password+FROM+users--&password=x"
```

### API Response
```bash
curl -H "Accept: application/json" http://localhost:8080/.env
```

### Challenge Flow
```bash
curl http://localhost:8080/shield/challenge?redirect=/home
```

## Routes

| Method | URI | Description |
|--------|-----|-------------|
| GET | `/` | Home |
| GET | `/home` | Home |
| GET | `/login` | Login form |
| POST | `/login` | Login submit |
| GET | `/api/users` | API endpoint |
| POST | `/api/login` | API login |
| GET | `/shield/challenge` | Challenge page |
| POST | `/shield/challenge/verify` | Challenge verify |
