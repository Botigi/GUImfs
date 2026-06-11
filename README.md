# MeterpreterViz (GUImfs)

Interface pédagogique locale Flask + Tailwind qui sert de surcouche visuelle pour une session Meterpreter via MSFRPC.

## Stack
- Backend: Flask
- Frontend: HTML + Vanilla JS + Tailwind CDN
- Bridge: `pymetasploit3`

## Arborescence
```
GUImfs/
├── app.py
├── msf_bridge.py
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── app.js
├── .gitignore
└── README.md
```

## Démarrage
```bash
# Terminal 1
msfrpcd -P password -S -f

# Terminal 2
pip install -r requirements.txt
python app.py
```

Ouvrir: http://localhost:5000

## API principales
- `GET /api/status`
- `POST /api/cmd/<command>`
- `GET /api/screenshot`
- `GET /api/ps`
- `GET /api/sysinfo`
- `POST /api/file/upload`
- `POST /api/file/download`

Toutes les actions sont journalisées dans `session.log`.
